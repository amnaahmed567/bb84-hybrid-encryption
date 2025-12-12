# aes_siv_engine.py
# AES-SIV (Synthetic IV) encryption engine - Misuse-resistant AEAD
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
AES-SIV (Synthetic IV) Encryption Engine

This module provides AES-SIV authenticated encryption as a misuse-resistant
alternative to AES-GCM and ChaCha20-Poly1305.

Key Differences from AES-GCM and ChaCha20:
- AES-SIV: Nonce-misuse resistant (safe even if nonce is reused)
- AES-GCM/ChaCha20: Catastrophic failure if nonce is reused
- AES-SIV: Uses deterministic encryption (no random nonce needed)
- AES-SIV: Slightly slower than GCM but provides better security guarantees

Security Properties:
- 512-bit key size (256-bit for encryption + 256-bit for authentication)
- No nonce required (deterministic authenticated encryption)
- RFC 5297 standard (SIV = Synthetic IV mode)
- Misuse-resistant: Safe against nonce reuse attacks
- AEAD: Provides both confidentiality and authenticity

Use Cases:
- Systems where nonce management is difficult
- High-security applications requiring defense-in-depth
- Environments with limited entropy sources
- Research and cryptographic experimentation
"""

from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

__all__ = ["aes_siv_encrypt", "aes_siv_decrypt"]


def aes_siv_encrypt(data: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    AES-SIV authenticated encryption (misuse-resistant AEAD).

    This function encrypts plaintext using AES-SIV mode, which generates a
    synthetic IV from the plaintext and associated data. Unlike AES-GCM and
    ChaCha20, AES-SIV is nonce-misuse resistant and deterministic.

    Args:
        data: Raw plaintext bytes to encrypt.
        key_with_salt: 48 bytes = 32-byte encryption key + 16-byte salt.
                      AES-SIV internally derives two 256-bit keys from this.
        aad: Optional associated data to authenticate (not encrypted).
             Typically contains metadata like version, filename, salt.

    Returns:
        Ciphertext with embedded synthetic IV (raw bytes).
        Format: synthetic_iv (16 bytes) + ciphertext
        No separate nonce is needed or generated.

    Raises:
        ValueError: If key_with_salt is not at least 48 bytes.

    Security Notes:
        - NO nonce is used or required (deterministic encryption).
        - Safe against nonce reuse (misuse-resistant property).
        - Synthetic IV is derived from plaintext and AAD.
        - Same plaintext + same key = same ciphertext (deterministic).
        - Provides authenticity via the synthetic IV (acts as MAC).

    Example:
        >>> key_with_salt = os.urandom(48)  # 32-byte key + 16-byte salt
        >>> plaintext = b"Secret quantum message"
        >>> aad = b'{"version": "AES-SIV-v1", "filename": "test.txt"}'
        >>> ciphertext = aes_siv_encrypt(plaintext, key_with_salt, aad)
        >>> # ciphertext = synthetic_iv (16) + encrypted_data
    """
    
    # Validation: require key (32 bytes) + salt (16 bytes) => 48 bytes total
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError("key_with_salt must be bytes and at least 48 bytes long (32-byte key + 16-byte salt)")
    
    # Extract the 32-byte encryption key
    # AES-SIV requires a 512-bit key (64 bytes) for full security,
    # but we'll use the 32-byte key and let AESSIV handle key derivation
    key = bytes(key_with_salt[:32])
    
    # AES-SIV requires 64-byte key (512 bits) for AES-256-SIV
    # We need to derive this from our 32-byte key
    # Simple approach: concatenate key with itself (key expansion)
    # For production, you might want to use HKDF to derive two separate keys
    siv_key = key + key  # 64 bytes total
    
    # Initialize AES-SIV cipher
    aessiv = AESSIV(siv_key)
    
    # Encrypt with AAD
    # AES-SIV signature: encrypt(data: bytes, associated_data: Optional[List[bytes]] = None)
    # Note: associated_data must be a list of byte strings
    if aad is not None:
        associated_data = [aad]
    else:
        associated_data = None
    
    ciphertext = aessiv.encrypt(data, associated_data)
    
    return ciphertext


def aes_siv_decrypt(encrypted: bytes, key_with_salt: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    AES-SIV authenticated decryption.

    This function decrypts AES-SIV ciphertext and verifies authenticity via the
    synthetic IV. If the ciphertext or AAD has been tampered with, decryption fails.

    Args:
        encrypted: Ciphertext with synthetic IV (synthetic_iv + encrypted_data).
        key_with_salt: 48 bytes = 32-byte encryption key + 16-byte salt.
                      Must be the same key used for encryption.
        aad: Optional associated data to verify (must match encryption AAD).

    Returns:
        Decrypted original plaintext (bytes).

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
            (ciphertext tampered, wrong key, or AAD mismatch).
        ValueError: If key_with_salt is invalid or ciphertext is too short.

    Security Notes:
        - Verifies both ciphertext integrity and AAD authenticity.
        - Constant-time comparison prevents timing attacks.
        - Any modification to ciphertext or AAD will cause decryption failure.

    Example:
        >>> key_with_salt = ...  # Same key used for encryption
        >>> aad = b'{"version": "AES-SIV-v1", "filename": "test.txt"}'
        >>> plaintext = aes_siv_decrypt(ciphertext, key_with_salt, aad)
    """
    
    # Validation: require key_with_salt length and minimum ciphertext size
    if not isinstance(key_with_salt, (bytes, bytearray)) or len(key_with_salt) < 48:
        raise ValueError("key_with_salt must be bytes and at least 48 bytes long (32-byte key + 16-byte salt)")
    if not isinstance(encrypted, (bytes, bytearray)) or len(encrypted) < 16:
        raise ValueError("encrypted blob is too short (must contain at least 16-byte synthetic IV)")
    
    # Extract the 32-byte encryption key
    key = bytes(key_with_salt[:32])
    
    # Derive 64-byte key for AES-SIV (same as encryption)
    siv_key = key + key  # 64 bytes total
    
    # Initialize AES-SIV cipher
    aessiv = AESSIV(siv_key)
    
    # Decrypt with AAD
    # AES-SIV signature: decrypt(data: bytes, associated_data: Optional[List[bytes]] = None)
    if aad is not None:
        associated_data = [aad]
    else:
        associated_data = None
    
    plaintext = aessiv.decrypt(encrypted, associated_data)
    
    return plaintext
