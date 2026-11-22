"""Vault sync -- seals and sends seeds to the electrum-vault panel.

This module runs inside the Electrum process (desktop and Android). It never
imports anything from the ``electrum`` package (that would create a circular
dependency). The calling plugin feeds it the seed as a plain string; this
module handles all the crypto (seal, fingerprint) and the HTTP POST.

The only external dependency is ``cryptography``, which Electrum already
ships on every platform (Windows, Linux, macOS, Android). No PyNaCl needed.

Security model:
- The seed is sealed on the device with the panel's X25519 public key (a
  NaCl crypto_box_seal equivalent built on ``cryptography``). The sealed
  blob travels over HTTPS; the panel stores it as-is. The seed never
  appears in plaintext outside this process.
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
# Crypto helpers (NaCl crypto_box_seal equivalent via ``cryptography``)
# ---------------------------------------------------------------------------
# SealedBox = ephemeral X25519 + XSalsa20-Poly1305. The ``cryptography``
# library has X25519 but not XSalsa20. We use an equivalent construction:
#   ephemeral X25519 key-agreement  +  AES-256-GCM
# with the shared secret derived through HKDF-SHA256.
#
# Format of the sealed blob:
#   ephemeral_pubkey (32 bytes) || nonce (12 bytes) || ciphertext+tag
#
# Only the panel's private key can recover the shared secret and decrypt.

def _seal(panel_pubkey_bytes: bytes, plaintext: bytes) -> bytes:
    """Seal *plaintext* so only the holder of the panel's X25519 private key
    can open it. Returns the sealed blob."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    panel_pub = X25519PublicKey.from_public_bytes(panel_pubkey_bytes)
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    shared = eph_priv.exchange(panel_pub)

    # Derive a 256-bit AES key from the shared secret.
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"electrum-vault-seal-v1",
    ).derive(shared)

    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return eph_pub_bytes + nonce + ct


def _unseal(panel_privkey_bytes: bytes, sealed: bytes) -> bytes:
    """Unseal a blob produced by ``_seal``. Used by the panel (and in tests)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    eph_pub_bytes = sealed[:32]
    nonce = sealed[32:44]
    ct = sealed[44:]

    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    panel_priv = X25519PrivateKey.from_private_bytes(panel_privkey_bytes)
    shared = panel_priv.exchange(eph_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"electrum-vault-seal-v1",
    ).derive(shared)

    return AESGCM(aes_key).decrypt(nonce, ct, None)


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
            # UA de navegador para passar pelo Browser Integrity Check do
            # Cloudflare (urllib padrao e bloqueado como bot).
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/json",
        },
        method="POST",
    )

    # TLS context -- verify certificate by default.
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
