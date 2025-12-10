# chacha20_engine.py
# ChaCha20-Poly1305 encryption engine (alternative to AES-GCM)
# Implements authenticated encryption with associated data (AEAD)
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

"""
ChaCha20-Poly1305 Encryption Engine

This module provides ChaCha20-Poly1305 authenticated encryption as an alternative
to AES-GCM. Both are AEAD (Authenticated Encryption with Associated Data) ciphers
that provide confidentiality and integrity.

Key Differences from AES-GCM:
- ChaCha20: Stream cipher (software-optimized, no hardware requirements)
- AES-GCM: Block cipher (hardware-accelerated on modern CPUs with AES-NI)
- ChaCha20: Better performance on devices without AES-NI
- Both: Equivalent 256-bit security level with authenticated encryption

Security Properties:
- 256-bit key size (quantum-resistant for decades)
- 96-bit (12-byte) nonce (must never be reused with same key)
- Poly1305 MAC for authentication (128-bit security)
- AEAD: Encrypts plaintext + authenticates associated data
"""

import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = ["chacha20_encrypt", "chacha20_decrypt"]


def chacha20_encrypt(data: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    ChaCha20-Poly1305 authenticated encryption (AEAD).

    This function encrypts plaintext and authenticates both the ciphertext and
    associated data (AAD) using ChaCha20-Poly1305. The nonce is randomly generated
    and prepended to the output.

    Args:
        data: Raw plaintext bytes to encrypt.
        key_with_salt: 48 bytes = 32-byte ChaCha20 key + 16-byte salt.
                      The salt is included for API compatibility with AES-GCM
                      but only the first 32 bytes are used as the encryption key.
        aad: Optional associated data to authenticate (not encrypted).
             Typically contains metadata like version, filename, salt.

    Returns:
        nonce (12 bytes) + ciphertext_with_tag as raw bytes.
        The Poly1305 authentication tag (16 bytes) is appended by ChaCha20Poly1305.

    Raises:
        ValueError: If key_with_salt is not at least 48 bytes.

    Security Notes:
        - Nonce is 12 bytes (96 bits) and randomly generated per encryption.
        - NEVER reuse a nonce with the same key (breaks security completely).
        - The returned blob is: nonce || ciphertext || poly1305_tag
        - Tag length is 16 bytes (128-bit authentication).

    Example:
        >>> key_with_salt = os.urandom(48)  # 32-byte key + 16-byte salt
        >>> plaintext = b"Secret quantum message"
        >>> aad = b'{"version": "ChaCha20-v1", "filename": "test.txt"}'
        >>> encrypted = chacha20_encrypt(plaintext, key_with_salt, aad)
        >>> # encrypted = nonce (12) + ciphertext + tag (16)
    """
    # Validate input
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError(
            "key_with_salt must be bytes and at least 48 bytes long "
            "(32-byte key + 16-byte salt)"
        )

    # Extract 32-byte ChaCha20 key (ignore salt for encryption, kept for API compatibility)
    key = bytes(key_with_salt[:32])
    
    # Generate random 12-byte nonce (CRITICAL: must be unique per encryption)
    nonce = os.urandom(12)

    # Initialize ChaCha20-Poly1305 cipher
    cipher = ChaCha20Poly1305(key)
    
    # Encrypt and authenticate
    # Returns: ciphertext || poly1305_tag (tag is 16 bytes)
    ciphertext_with_tag = cipher.encrypt(nonce, data, associated_data=aad)

    # Return nonce prepended to ciphertext+tag
    return nonce + ciphertext_with_tag


def chacha20_decrypt(encrypted: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    ChaCha20-Poly1305 authenticated decryption (AEAD).

    This function decrypts ciphertext and verifies the Poly1305 authentication tag.
    If the tag is invalid (data tampered), an InvalidTag exception is raised.

    Args:
        encrypted: nonce (12 bytes) + ciphertext_with_tag.
                  The tag is the last 16 bytes of ciphertext_with_tag.
        key_with_salt: 48 bytes = 32-byte ChaCha20 key + 16-byte salt.
        aad: Optional associated data that was authenticated during encryption.
             Must match the AAD used during encryption or authentication fails.

    Returns:
        Decrypted plaintext (bytes).

    Raises:
        ValueError: If key_with_salt or encrypted blob is invalid size.
        cryptography.exceptions.InvalidTag: If authentication fails (tampered data).

    Security Notes:
        - Authentication MUST be verified before trusting decrypted plaintext.
        - InvalidTag indicates either:
          1. Wrong decryption key
          2. Tampered ciphertext
          3. Tampered AAD
          4. Wrong nonce
        - Always catch InvalidTag and reject the data immediately.

    Example:
        >>> try:
        ...     plaintext = chacha20_decrypt(encrypted, key_with_salt, aad)
        ...     print(f"Decrypted: {plaintext}")
        ... except InvalidTag:
        ...     print("Authentication failed! Data tampered or wrong key.")
    """
    # Validate input
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError(
            "key_with_salt must be bytes and at least 48 bytes long "
            "(32-byte key + 16-byte salt)"
        )
    
    # ChaCha20-Poly1305 requires: nonce (12) + ciphertext + tag (16)
    # Minimum size: 12 + 0 + 16 = 28 bytes
    if not isinstance(encrypted, (bytes, bytearray)) or len(encrypted) < 28:
        raise ValueError(
            "Encrypted blob is too short to contain nonce (12 bytes) and Poly1305 tag (16 bytes)"
        )

    # Extract 32-byte ChaCha20 key
    key = bytes(key_with_salt[:32])
    
    # Extract nonce and ciphertext+tag
    nonce = encrypted[:12]
    ciphertext_with_tag = encrypted[12:]

    # Initialize ChaCha20-Poly1305 cipher
    cipher = ChaCha20Poly1305(key)
    
    # Decrypt and verify authentication tag
    # Raises InvalidTag if authentication fails
    return cipher.decrypt(nonce, ciphertext_with_tag, associated_data=aad)


# ----------------------------------------------------------------------------
# Performance Comparison: ChaCha20 vs AES-GCM
# ----------------------------------------------------------------------------
# 
# Hardware WITH AES-NI (Intel/AMD modern CPUs):
#   - AES-GCM:    ~2-5 GB/s (hardware-accelerated)
#   - ChaCha20:   ~500 MB/s (software-only)
#   - Winner: AES-GCM (4-10x faster)
#
# Hardware WITHOUT AES-NI (ARM, older CPUs, mobile):
#   - AES-GCM:    ~50-100 MB/s (software-only, slow)
#   - ChaCha20:   ~500-800 MB/s (optimized software)
#   - Winner: ChaCha20 (5-15x faster)
#
# Recommendation:
#   - Use AES-GCM on modern x86/x64 servers/desktops (default)
#   - Use ChaCha20 on ARM devices, mobile, or legacy systems
#   - Both provide equivalent 256-bit security
#
# ----------------------------------------------------------------------------
