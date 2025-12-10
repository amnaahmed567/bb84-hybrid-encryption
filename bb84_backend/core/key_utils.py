# key_utils.py
# Utilities for BB84 quantum key post-processing and AES-256 derivation.
# Includes entropy validation, conversion, and key derivation helpers (AEAD used for authentication).
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


from typing import List
import os

# Use HKDF from the cryptography library for key derivation
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def check_key_entropy(bits: List[int]) -> bool:
    """
    Checks whether a bit sequence has acceptable entropy (i.e., balanced 0s and 1s).
    
    Returns:
        True if entropy is acceptable, False otherwise.
    """
    ones = sum(bits)
    balance_ratio = abs(ones - len(bits) / 2) / len(bits)
    return balance_ratio < 0.4  # Threshold can be tightened if needed

def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Converts a list of bits (0/1 integers) to a bytes object.
    Pads with 0s to ensure byte alignment.

    Args:
        bits: List of 0s and 1s

    Returns:
        Byte representation of bit list
    """
    padding = (8 - len(bits) % 8) % 8
    bits += [0] * padding
    return bytes(
        int("".join(map(str, bits[i:i+8])), 2)
        for i in range(0, len(bits), 8)
    )

def bytes_to_bits(data: bytes) -> List[int]:
    """
    Converts bytes into a flat list of bits (0/1 integers).

    Args:
        data: Byte input

    Returns:
        List of bits
    """
    return [int(bit) for byte in data for bit in f"{byte:08b}"]

def derive_aes_key_from_bits(bits: List[int], salt: bytes = None, iterations: int = 100_000) -> bytes:
    """
    Derives a secure 256-bit AES key from quantum-generated bits using HKDF-SHA256.
    The function preserves the previous API by returning 48 bytes: 32-byte key + 16-byte salt.

    Notes:
    - The `iterations` parameter is retained for API compatibility but is ignored for HKDF.
    - HKDF provides a robust KDF; callers should treat the returned salt as the salt
      that must be reused during key reconstruction.

    Args:
        bits: BB84 shared bits
        salt: Optional fixed salt (for verification); auto-generated if None
        iterations: Ignored (kept for backward compatibility)

    Returns:
        Concatenated `key (32 bytes) || salt (16 bytes)` as bytes
    """
    raw = bits_to_bytes(bits)
    salt = salt or os.urandom(16)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"bb84-aes-key-derivation",
        backend=default_backend(),
    )

    key = hkdf.derive(raw)
    return key + salt


def derive_separated_keys(bits: List[int], salt: bytes = None) -> dict:
    """
    Derives multiple separated keys from quantum bits using HKDF with different info parameters.
    This implements key separation to prevent key reuse attacks.
    
    Each key is derived independently using HKDF with a unique 'info' parameter,
    ensuring cryptographic separation between different use cases.
    
    Args:
        bits: BB84 shared bits
        salt: Optional fixed salt; auto-generated if None
    
    Returns:
        Dictionary containing:
        - 'encryption_key': 32-byte key for AES encryption
        - 'auth_key': 32-byte key for authentication (if needed separately)
        - 'signature_key': 32-byte key for signatures (if needed)
        - 'salt': 16-byte salt used for all derivations
    
    Security Note:
        Using different 'info' parameters ensures that even if one key is compromised,
        the others remain secure due to the one-way property of HKDF.
    """
    raw = bits_to_bytes(bits)
    salt = salt or os.urandom(16)
    
    # Derive encryption key
    hkdf_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"bb84-aes-encryption-key",
        backend=default_backend(),
    )
    encryption_key = hkdf_enc.derive(raw)
    
    # Derive authentication key (for future HMAC if needed separately from AEAD)
    hkdf_auth = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"bb84-authentication-key",
        backend=default_backend(),
    )
    auth_key = hkdf_auth.derive(raw)
    
    # Derive signature key (for internal signing operations if needed)
    hkdf_sig = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"bb84-signature-key",
        backend=default_backend(),
    )
    signature_key = hkdf_sig.derive(raw)
    
    return {
        'encryption_key': encryption_key,
        'auth_key': auth_key,
        'signature_key': signature_key,
        'salt': salt
    }


def derive_chacha20_key_from_bits(bits: List[int], salt: bytes = None) -> bytes:
    """
    Derives a secure 256-bit ChaCha20 key from quantum-generated bits using HKDF-SHA256.
    This function mirrors derive_aes_key_from_bits() but uses a different info parameter
    for cryptographic separation between AES and ChaCha20 keys.
    
    Args:
        bits: BB84 shared bits
        salt: Optional fixed salt (for verification); auto-generated if None
    
    Returns:
        Concatenated `key (32 bytes) || salt (16 bytes)` as bytes (48 bytes total)
    
    Security Note:
        - Uses info="bb84-chacha20-encryption-key" to ensure cryptographic separation
        - ChaCha20 keys and AES keys are derived independently (no key reuse)
        - Salt must be transmitted alongside ciphertext for decryption
    
    Example:
        >>> quantum_bits = [1, 0, 1, 1, 0, 0, 1, 0] * 32  # 256 bits
        >>> key_with_salt = derive_chacha20_key_from_bits(quantum_bits)
        >>> chacha20_key = key_with_salt[:32]  # 32-byte key
        >>> salt = key_with_salt[32:]           # 16-byte salt
    """
    raw = bits_to_bytes(bits)
    salt = salt or os.urandom(16)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"bb84-chacha20-encryption-key",  # Different from AES to prevent key reuse
        backend=default_backend(),
    )
    
    key = hkdf.derive(raw)
    return key + salt


# Note: AES-GCM AEAD provides built-in authentication, so separate auth_key
# is primarily for future extensibility or additional MAC layers.
# The key separation pattern above prevents key reuse attacks.
