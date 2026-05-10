"""
encryption.py — AES-256-GCM Encryption / Decryption
======================================================
Uses AES-256 in GCM (Galois/Counter Mode) which provides:
  • Confidentiality  — nobody can read the data without the key
  • Integrity        — any tampering is detected (authentication tag)
  • Authenticity     — data origin is verified

Wire format (all base64-encoded together):
  [ 12-byte nonce ][ ciphertext ][ 16-byte auth tag ]
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import AES_KEY


# One shared AESGCM instance — thread-safe and reusable
_aesgcm = AESGCM(AES_KEY)


def encrypt(plaintext: str) -> str:
    """
    Encrypt a UTF-8 string.

    Returns a base64 string in the format:
        base64( nonce[12] + ciphertext + tag[16] )
    """
    nonce = os.urandom(12)                          # 96-bit random nonce (GCM standard)
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext_with_tag = _aesgcm.encrypt(nonce, plaintext_bytes, None)
    # Concatenate nonce + ciphertext+tag, then base64-encode the whole blob
    blob = nonce + ciphertext_with_tag
    return base64.b64encode(blob).decode("utf-8")


def decrypt(encrypted_b64: str) -> str:
    """
    Decrypt a base64 string produced by encrypt().

    Raises cryptography.exceptions.InvalidTag if the data was tampered with.
    """
    blob = base64.b64decode(encrypted_b64.encode("utf-8"))
    nonce              = blob[:12]                  # first 12 bytes are the nonce
    ciphertext_with_tag = blob[12:]                 # rest is ciphertext + auth tag
    plaintext_bytes = _aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8")


# ── Quick self-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = '{"vehicle_id": "AV-001", "speed": 72.4, "event": "HARD_BRAKE"}'
    enc = encrypt(sample)
    dec = decrypt(enc)
    print("Original :", sample)
    print("Encrypted:", enc[:60], "...")
    print("Decrypted:", dec)
    print("Match     :", sample == dec)