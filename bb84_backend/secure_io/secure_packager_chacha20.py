# secure_packager_chacha20.py
# ChaCha20-Poly1305 secure packaging (alternative to AES-GCM)
# Provides identical security guarantees with different cipher primitive
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ----------------------------------------------------------------------------

"""
ChaCha20-Poly1305 Secure Packaging

This module provides ChaCha20-Poly1305 encryption as an alternative to AES-GCM
for the BB84 hybrid encryption system. It maintains identical security properties:
- AEAD (Authenticated Encryption with Associated Data)
- Post-quantum Dilithium5 signatures
- HKDF key derivation from quantum bits
- Metadata authentication (version, filename, salt)
- Verify-before-decrypt optimization

Security equivalence with AES-GCM packager:
✅ 256-bit encryption keys (ChaCha20 vs AES)
✅ AEAD authentication (Poly1305 vs GCM)
✅ Post-quantum signatures (Dilithium5)
✅ HKDF-SHA256 key derivation
✅ Metadata in AAD (authenticated but not encrypted)
✅ Signature verification before decryption
"""

import json
import base64
from typing import List, Tuple, Dict
import os
from cryptography.exceptions import InvalidTag

# ChaCha20 encryption and key utilities
from bb84_backend.core.chacha20_engine import chacha20_encrypt, chacha20_decrypt
from bb84_backend.core.key_utils import derive_chacha20_key_from_bits

# Post-quantum signature (same as AES-GCM packager)
try:
    from dilithium import Dilithium, DEFAULT_PARAMETERS
    ps = DEFAULT_PARAMETERS.get("dilithium5") or next(iter(DEFAULT_PARAMETERS.values()))
    dilithium_obj = Dilithium(parameter_set=ps)
    PQCRYPTO_AVAILABLE = True
except Exception as e:
    print(f"[secure_packager_chacha20] Dilithium unavailable: {e}")
    PQCRYPTO_AVAILABLE = False
    dilithium_obj = None


def _dilithium_keypair_pk_sk(dil) -> Tuple[bytes, bytes]:
    """Generate Dilithium keypair (identical to AES-GCM packager)."""
    seed = os.urandom(64)
    pair = dil.keygen(seed)
    if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
        raise RuntimeError("Unexpected keygen output; expected (pk_bytes, sk_bytes).")
    pk, sk = pair
    if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
        raise RuntimeError("Keygen did not return raw bytes for (pk, sk).")
    return bytes(pk), bytes(sk)


def save_encrypted_file_chacha20(
    plaintext: bytes,
    key_a_bits: List[int],
    original_filename: str = "file"
) -> bytes:
    """
    Encrypts file using ChaCha20-Poly1305 and returns a secure JSON package.
    
    This function provides identical security to save_encrypted_file() but uses
    ChaCha20-Poly1305 instead of AES-GCM. The package format is the same except
    for the version field.
    
    Encryption Flow:
    1. Derive ChaCha20 key from quantum bits using HKDF (info="bb84-chacha20-encryption-key")
    2. Build internal payload with plaintext
    3. Construct AAD from metadata (version, filename, salt)
    4. Encrypt with ChaCha20-Poly1305 (12-byte nonce, Poly1305 tag)
    5. Sign outer package with Dilithium5 post-quantum signature
    
    Args:
        plaintext: Raw file bytes to encrypt
        key_a_bits: Alice's BB84 quantum key bits (sender's key)
        original_filename: Original filename for metadata
    
    Returns:
        JSON package as bytes containing:
        - ciphertext: Base64-encoded (nonce + encrypted_data + poly1305_tag)
        - salt: Base64-encoded 16-byte salt for HKDF
        - version: "ChaCha20-v1" (identifies cipher)
        - original_filename: Authenticated in AAD
        - pq_signature: Dilithium5 signature
        - pq_public_key: Dilithium5 public key
    
    Security Properties:
        - Quantum key distribution: BB84 protocol ensures key secrecy
        - Key derivation: HKDF-SHA256 with unique salt per encryption
        - Encryption: ChaCha20-Poly1305 AEAD (256-bit key, 128-bit auth)
        - Metadata: Authenticated via AAD (prevents tampering)
        - Signature: Post-quantum Dilithium5 (NIST Level 5 security)
    
    Example:
        >>> plaintext = b"Top secret quantum data"
        >>> alice_bits = [1, 0, 1, 1, 0, 0] * 43  # 256+ bits from BB84
        >>> package = save_encrypted_file_chacha20(plaintext, alice_bits, "secret.txt")
        >>> # Send package to Bob (public channel safe due to encryption + signature)
    """
    # 1) Derive ChaCha20 key with salt using Key A (Alice's quantum key)
    key_with_salt = derive_chacha20_key_from_bits(key_a_bits)

    # 2) Build internal payload (encrypted, not exposed)
    internal_payload = {
        "file_bytes_b64": base64.b64encode(plaintext).decode("utf-8"),
    }
    internal_bytes = json.dumps(internal_payload).encode("utf-8")

    # 3) Build AAD (authenticated but not encrypted)
    version = "ChaCha20-v1"  # Different from "AES-GCM-v1" to identify cipher
    salt_b64 = base64.b64encode(key_with_salt[32:]).decode("utf-8")
    aad_obj = {
        "version": version,
        "original_filename": original_filename,
        "salt": salt_b64
    }
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 4) Encrypt with ChaCha20-Poly1305 AEAD
    encrypted = chacha20_encrypt(internal_bytes, key_with_salt, aad=aad_bytes)

    # 5) Build outer package (public, authenticated via signature)
    package = {
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
        "salt": salt_b64,
        "version": version,
        "original_filename": original_filename,
    }

    # 6) Require post-quantum signature
    if not PQCRYPTO_AVAILABLE:
        raise RuntimeError("Dilithium module not available — cannot sign the package.")

    # 7) Generate Dilithium keypair and sign
    pk_bytes, sk_bytes = _dilithium_keypair_pk_sk(dilithium_obj)
    package_bytes = json.dumps(package).encode("utf-8")
    signature = dilithium_obj.sign_with_input(sk_bytes, package_bytes)

    # 8) Attach signature and public key
    package["pq_signature"] = base64.b64encode(signature).decode("utf-8")
    package["pq_public_key"] = base64.b64encode(pk_bytes).decode("utf-8")

    # 9) Return complete package
    return json.dumps(package).encode("utf-8")


def load_and_decrypt_bytes_chacha20(
    package_bytes: bytes,
    key_b_bits: List[int]
) -> Tuple[bytes, Dict[str, str], bool]:
    """
    Loads and decrypts ChaCha20-Poly1305 encrypted package using Bob's quantum key.
    
    This function mirrors load_and_decrypt_bytes() but uses ChaCha20-Poly1305
    for decryption. It implements the same security optimizations:
    - Verify-before-decrypt (signature checked first)
    - AEAD authentication (Poly1305 tag verification)
    - Key confirmation (via BB84 protocol)
    
    Decryption Flow:
    1. Parse JSON package
    2. ✅ Verify Dilithium5 signature FIRST (reject if invalid)
    3. Derive ChaCha20 key from Bob's quantum bits + transmitted salt
    4. Reconstruct AAD (must match encryption-time AAD)
    5. Decrypt with ChaCha20-Poly1305 (verifies Poly1305 tag)
    6. Extract plaintext and metadata
    
    Args:
        package_bytes: Encrypted JSON package from save_encrypted_file_chacha20()
        key_b_bits: Bob's BB84 quantum key bits (must match Alice's key after reconciliation)
    
    Returns:
        Tuple of:
        - plaintext (bytes): Decrypted file data (empty if failed)
        - metadata (dict): Original filename and extension
        - success (bool): True if all verifications passed
    
    Security Checks:
        1. Dilithium signature verification (post-quantum security)
        2. Poly1305 authentication tag (AEAD integrity)
        3. AAD verification (metadata tampering detection)
        4. Key confirmation (implicit via successful decryption)
    
    Failure Modes:
        - Returns (b"", {}, False) if:
          * Signature verification fails
          * Wrong decryption key (Bob's key ≠ Alice's key)
          * Tampered ciphertext (Poly1305 tag invalid)
          * Tampered AAD (metadata modified)
          * Malformed package structure
    
    Example:
        >>> # Bob receives package from Alice
        >>> bob_bits = [1, 0, 1, 1, 0, 0] * 43  # Bob's BB84 key (matches Alice after reconciliation)
        >>> plaintext, metadata, success = load_and_decrypt_bytes_chacha20(package, bob_bits)
        >>> if success:
        ...     print(f"Decrypted {metadata['original_filename']}: {plaintext}")
        ... else:
        ...     print("Decryption failed! Key mismatch or tampered data.")
    """
    # 1) Parse outer package
    try:
        package = json.loads(package_bytes.decode("utf-8"))
    except Exception:
        return b"", {}, False

    # ===== OPTIMIZATION: Verify signature FIRST (before decryption) =====
    # 2) Verify post-quantum signature (reject immediately if invalid)
    if PQCRYPTO_AVAILABLE and "pq_signature" in package and "pq_public_key" in package:
        try:
            pq_signature = base64.b64decode(package["pq_signature"])
            pq_public_key = base64.b64decode(package["pq_public_key"])
            
            # Rebuild unsigned package for verification
            unsigned_package = {
                k: v for k, v in package.items()
                if k not in ("pq_signature", "pq_public_key")
            }
            unsigned_bytes = json.dumps(unsigned_package).encode("utf-8")
            
            # Verify signature (reject before attempting expensive decryption)
            if not dilithium_obj.verify(pq_public_key, unsigned_bytes, pq_signature):
                return b"", {}, False
        except Exception:
            return b"", {}, False
    else:
        # No signature or PQC unavailable -> reject
        return b"", {}, False

    # 3) Extract encrypted components
    try:
        salt = base64.b64decode(package["salt"])
        ciphertext = base64.b64decode(package["ciphertext"])
        version = package.get("version", "")
        original_filename = package.get("original_filename", "decrypted_file")
    except Exception:
        return b"", {}, False

    # 4) Derive ChaCha20 key using Bob's bits and transmitted salt
    candidate_key = derive_chacha20_key_from_bits(key_b_bits, salt)

    # 5) Rebuild AAD (must match encryption-time AAD)
    aad_obj = {
        "version": version,
        "original_filename": original_filename,
        "salt": package["salt"]
    }
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 6) Decrypt and verify Poly1305 authentication tag
    try:
        # chacha20_decrypt raises InvalidTag if authentication fails
        internal_bytes = chacha20_decrypt(ciphertext, candidate_key, aad=aad_bytes)
    except InvalidTag:
        # Authentication failed: wrong key or tampered ciphertext
        return b"", {}, False
    except Exception:
        return b"", {}, False

    # 7) Parse internal payload
    try:
        internal = json.loads(internal_bytes.decode("utf-8"))
        plaintext = base64.b64decode(internal["file_bytes_b64"])
    except Exception:
        return b"", {}, False

    # 8) Extract metadata
    metadata = {
        "original_filename": original_filename,
        "extension": original_filename.split(".")[-1] if "." in original_filename else "bin",
    }

    # Success: signature verified first, then AEAD authentication passed
    return plaintext, metadata, True


# ----------------------------------------------------------------------------
# ChaCha20 vs AES-GCM: When to Use Which?
# ----------------------------------------------------------------------------
#
# Use ChaCha20-Poly1305 when:
# ✅ Running on devices WITHOUT AES-NI hardware acceleration
# ✅ ARM processors (mobile, Raspberry Pi, embedded systems)
# ✅ Older CPUs without AES instruction set
# ✅ Need constant-time encryption (no timing attacks via cache)
# ✅ Software-only environments (no hardware crypto)
#
# Use AES-GCM when:
# ✅ Running on modern x86/x64 CPUs with AES-NI
# ✅ Need maximum performance on Intel/AMD servers
# ✅ Hardware acceleration available (4-10x faster than ChaCha20)
# ✅ Standard enterprise deployment (AES is more widely audited)
#
# Security: Both are equivalent (256-bit keys, AEAD authentication)
# Performance: Depends on hardware (measure on target platform)
#
# This implementation allows you to choose per-file:
#   - save_encrypted_file()         → AES-GCM
#   - save_encrypted_file_chacha20() → ChaCha20-Poly1305
#
# Both use the same BB84 quantum key distribution and Dilithium signatures.
# ----------------------------------------------------------------------------
