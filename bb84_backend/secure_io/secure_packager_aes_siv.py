# secure_packager_aes_siv.py
# AES-SIV (Synthetic IV) secure packaging - Misuse-resistant alternative
# Provides nonce-misuse resistance with deterministic encryption
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ----------------------------------------------------------------------------

"""
AES-SIV Secure Packaging

This module provides AES-SIV (Synthetic IV) encryption as a misuse-resistant
alternative to AES-GCM and ChaCha20-Poly1305 for the BB84 hybrid encryption system.

Key Advantages over AES-GCM/ChaCha20:
- Nonce-misuse resistant (safe even if nonce management fails)
- Deterministic encryption (no random nonce needed)
- Simpler implementation (no nonce generation/storage)
- Same security level when used correctly

Security equivalence:
✅ 256-bit encryption keys (AES-SIV)
✅ AEAD authentication (Synthetic IV acts as MAC)
✅ Post-quantum signatures (Dilithium5)
✅ HKDF-SHA256 key derivation
✅ Metadata in AAD (authenticated but not encrypted)
✅ Signature verification before decryption
✅ Misuse-resistant (unique selling point)
"""

import json
import base64
from typing import List, Tuple, Dict
import os
from cryptography.exceptions import InvalidTag

# AES-SIV encryption and key utilities
from bb84_backend.core.aes_siv_engine import aes_siv_encrypt, aes_siv_decrypt
from bb84_backend.core.key_utils import derive_aes_key_from_bits

# Post-quantum signature (same as other packagers)
try:
    from dilithium import Dilithium, DEFAULT_PARAMETERS
    ps = DEFAULT_PARAMETERS.get("dilithium5") or next(iter(DEFAULT_PARAMETERS.values()))
    dilithium_obj = Dilithium(parameter_set=ps)
    PQCRYPTO_AVAILABLE = True
except Exception as e:
    print(f"[secure_packager_aes_siv] Dilithium unavailable: {e}")
    PQCRYPTO_AVAILABLE = False
    dilithium_obj = None


def _dilithium_keypair_pk_sk(dil) -> Tuple[bytes, bytes]:
    """Generate Dilithium keypair (identical to other packagers)."""
    seed = os.urandom(64)
    pair = dil.keygen(seed)
    if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
        raise RuntimeError("Unexpected keygen output; expected (pk_bytes, sk_bytes).")
    pk, sk = pair
    if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
        raise RuntimeError("Keygen did not return raw bytes for (pk, sk).")
    return bytes(pk), bytes(sk)


def save_encrypted_file_aes_siv(
    plaintext: bytes,
    key_a_bits: List[int],
    original_filename: str = "file"
) -> bytes:
    """
    Encrypts file using AES-SIV and returns a secure JSON package.
    
    This function provides misuse-resistant encryption using AES-SIV.
    Unlike AES-GCM and ChaCha20, AES-SIV is deterministic and requires no nonce.
    
    Encryption Flow:
    1. Derive AES key from quantum bits using HKDF (info="bb84-aes-encryption-key")
    2. Build internal payload with plaintext
    3. Construct AAD from metadata (version, filename, salt)
    4. Encrypt with AES-SIV (synthetic IV embedded, no nonce needed)
    5. Sign outer package with Dilithium5 post-quantum signature
    
    Args:
        plaintext: Raw file bytes to encrypt
        key_a_bits: Alice's BB84 quantum key bits (sender's key)
        original_filename: Original filename for metadata
    
    Returns:
        JSON package as bytes containing:
        - ciphertext: Base64-encoded (synthetic_iv + encrypted_data)
        - salt: Base64-encoded 16-byte salt for HKDF
        - version: "AES-SIV-v1" (identifies cipher)
        - original_filename: Authenticated in AAD
        - pq_signature: Dilithium5 signature
        - pq_public_key: Dilithium5 public key
        Note: NO nonce field (AES-SIV doesn't use nonces)
    
    Security Properties:
        - Quantum key distribution: BB84 protocol ensures key secrecy
        - Key derivation: HKDF-SHA256 with unique salt per encryption
        - Encryption: AES-SIV AEAD (256-bit key, deterministic)
        - Metadata: Authenticated via AAD (prevents tampering)
        - Signature: Post-quantum Dilithium5 (NIST Level 5 security)
        - Misuse-resistant: Safe against nonce reuse attacks
    
    Example:
        >>> plaintext = b"Top secret quantum data"
        >>> alice_bits = [1, 0, 1, 1, 0, 0] * 43  # 256+ bits from BB84
        >>> package = save_encrypted_file_aes_siv(plaintext, alice_bits, "secret.txt")
        >>> # Send package to Bob (public channel safe due to encryption + signature)
    """
    # 1) Derive AES key with salt using Key A (Alice's quantum key)
    # Using same HKDF as AES-GCM for consistency
    key_with_salt = derive_aes_key_from_bits(key_a_bits)

    # 2) Build internal payload (encrypted, not exposed)
    internal_payload = {
        "file_bytes_b64": base64.b64encode(plaintext).decode("utf-8"),
    }
    internal_bytes = json.dumps(internal_payload).encode("utf-8")

    # 3) Build AAD (authenticated but not encrypted)
    version = "AES-SIV-v1"  # Unique version identifier for AES-SIV
    salt_b64 = base64.b64encode(key_with_salt[32:]).decode("utf-8")
    aad_obj = {
        "version": version,
        "original_filename": original_filename,
        "salt": salt_b64
    }
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 4) Encrypt with AES-SIV AEAD
    # Note: NO nonce is generated or used
    encrypted = aes_siv_encrypt(internal_bytes, key_with_salt, aad=aad_bytes)

    # 5) Build outer package (public, authenticated via signature)
    package = {
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
        "salt": salt_b64,
        "version": version,
        "original_filename": original_filename,
        # Note: NO "nonce" field - AES-SIV doesn't use nonces
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


def load_and_decrypt_bytes_aes_siv(
    package_bytes: bytes,
    key_b_bits: List[int]
) -> Tuple[bytes, Dict[str, str], bool]:
    """
    Loads encrypted AES-SIV package and decrypts using derived key if valid.
    Validates post-quantum signature and key integrity before decrypting.
    
    Security Optimization: Verifies post-quantum signature BEFORE attempting decryption
    to prevent wasted computation on tampered packages.

    Args:
        package_bytes: Encrypted JSON package from save_encrypted_file_aes_siv()
        key_b_bits: Bob's BB84 quantum key bits (receiver's key, should match Alice's)

    Returns:
        Tuple of (plaintext, metadata, integrity_ok):
        - plaintext (bytes): Decrypted file data (empty if failed)
        - metadata (dict): Original filename and extension
        - integrity_ok (bool): True if signature + AEAD verified, False otherwise

    Security Checks:
        1. Dilithium5 signature verification (FIRST - prevent decryption attacks)
        2. Key derivation using Bob's quantum bits + stored salt
        3. AAD reconstruction (must match encryption AAD)
        4. AES-SIV decryption + authentication (synthetic IV verification)
        5. Internal payload parsing

    Example:
        >>> package = ...  # Received from Alice
        >>> bob_bits = [1, 0, 1, 1, 0, 0] * 43  # Bob's BB84 key
        >>> plaintext, metadata, ok = load_and_decrypt_bytes_aes_siv(package, bob_bits)
        >>> if ok:
        ...     print(f"Decrypted: {metadata['original_filename']}")
        ... else:
        ...     print("Authentication failed!")
    """
    # Parse outer package
    package = json.loads(package_bytes.decode("utf-8"))

    # ===== OPTIMIZATION: Verify signature FIRST (before expensive decryption) =====
    # 1) Verify post-quantum signature (if included)
    if PQCRYPTO_AVAILABLE and "pq_signature" in package and "pq_public_key" in package:
        pq_signature = base64.b64decode(package["pq_signature"])
        pq_public_key = base64.b64decode(package["pq_public_key"])

        # Rebuild outer package without signature fields for validation
        unsigned_package = {k: v for k, v in package.items() if k not in ("pq_signature", "pq_public_key")}
        unsigned_bytes = json.dumps(unsigned_package).encode("utf-8")

        try:
            # Verify Dilithium signature
            if not dilithium_obj.verify(pq_public_key, unsigned_bytes, pq_signature):
                # Signature invalid - reject immediately WITHOUT attempting decryption
                return b"", {}, False
        except Exception:
            # Signature verification failed - reject immediately
            return b"", {}, False
    else:
        # PQC available but no signature included -> invalid (reject before decryption)
        return b"", {}, False

    # 2) Extract outer encrypted components
    salt = base64.b64decode(package["salt"])
    ciphertext = base64.b64decode(package["ciphertext"])
    version = package.get("version", "")
    original_filename = package.get("original_filename", "decrypted_file")

    # 3) Derive AES key using Bob's bits and the stored salt
    candidate_key = derive_aes_key_from_bits(key_b_bits, salt)

    # 4) Rebuild AAD the same way it was constructed during encryption
    aad_obj = {
        "version": version,
        "original_filename": original_filename,
        "salt": package["salt"]
    }
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 5) Decrypt the internal payload (pass AAD)
    # aes_siv_decrypt will raise InvalidTag if authentication fails
    # This is now safe because we already verified the signature above
    try:
        internal_bytes = aes_siv_decrypt(ciphertext, candidate_key, aad=aad_bytes)
    except InvalidTag:
        # AEAD authentication failed (wrong key or tampered ciphertext)
        return b"", {}, False

    # 6) Parse internal payload (contains original file and protected fields)
    try:
        internal = json.loads(internal_bytes.decode("utf-8"))
    except Exception:
        return b"", {}, False

    # 7) Rehydrate original content
    try:
        plaintext = base64.b64decode(internal["file_bytes_b64"])
    except KeyError:
        return b"", {}, False

    # 8) Metadata (extracted from package)
    metadata = {
        "original_filename": original_filename,
        "extension": "bin",  # Default extension
    }

    # Success: signature verified first, then AEAD authentication passed
    return plaintext, metadata, True


# Module exports
__all__ = ["save_encrypted_file_aes_siv", "load_and_decrypt_bytes_aes_siv"]
