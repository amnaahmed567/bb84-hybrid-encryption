# aes_engine.py
# Independent AES-256 engine (military-grade), CBC mode with PKCS#7 padding.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["aes_encrypt", "aes_decrypt"]


def aes_encrypt(data: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    AES-256-GCM encryption (authenticated encryption).

    Args:
        data: Raw plaintext bytes.
        key_with_salt: 48 bytes = 32-byte AES key + 16-byte salt.

    Returns:
        nonce (12 bytes) + ciphertext_with_tag (ciphertext || tag) as raw bytes.

    Notes:
        - Uses a 12-byte nonce (recommended for GCM).
        - The returned blob contains nonce||ciphertext||tag so callers can store it
          and later call `aes_decrypt` with the same `key_with_salt`.
    """

    # Basic validation: require key (32 bytes) + salt (16 bytes) => 48 bytes total
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError("key_with_salt must be bytes and at least 48 bytes long (32-byte key + 16-byte salt)")

    key = bytes(key_with_salt[:32])
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data=aad)

    return nonce + ciphertext_with_tag


def aes_decrypt(encrypted: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    AES-256-GCM decryption.

    Args:
        encrypted: nonce (12 bytes) + ciphertext_with_tag.
        key_with_salt: 48 bytes = 32-byte AES key + 16-byte salt.

    Returns:
        Decrypted original plaintext (bytes).

    Raises:
        cryptography.exceptions.InvalidTag if authentication fails.
    """

    # Basic validation: require key_with_salt length and encrypted blob size (nonce + tag)
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError("key_with_salt must be bytes and at least 48 bytes long (32-byte key + 16-byte salt)")
    if not isinstance(encrypted, (bytes, bytearray)) or len(encrypted) < 12 + 16:
        raise ValueError("encrypted blob is too short to contain nonce and GCM tag")

    key = bytes(key_with_salt[:32])
    nonce = encrypted[:12]
    ciphertext_with_tag = encrypted[12:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=aad)
