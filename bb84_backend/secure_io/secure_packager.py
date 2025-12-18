# secure_packager.py
# Secure packaging and unpackaging of encrypted files with BB84, AES-GCM (AEAD), and post-quantum signature validation
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ----------------------------------------------------------------------------

import json
import base64
from typing import List, Tuple, Dict
import os
from cryptography.exceptions import InvalidTag

# Core AES encryption and key utilities
from bb84_backend.core.aes_engine import aes_encrypt, aes_decrypt
from bb84_backend.core.key_utils import (
    derive_aes_key_from_bits,
)

# Optional compression: prefer zstandard for speed/ratio, fallback to gzip
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except Exception:
    import gzip
    ZSTD_AVAILABLE = False

# ----------------------------------------------------------------------------
# Post-quantum (Dilithium) import — this build exposes DEFAULT_PARAMETERS
# and instance methods: keygen(seed), sign_with_input(sk, m), verify(pk, m, sig)
# ----------------------------------------------------------------------------
try:
    from dilithium import Dilithium, DEFAULT_PARAMETERS
    # Prefer Dilithium5 if present (keys are lowercase in this build)
    ps = DEFAULT_PARAMETERS.get("dilithium5") or next(iter(DEFAULT_PARAMETERS.values()))
    dilithium_obj = Dilithium(parameter_set=ps)
    PQCRYPTO_AVAILABLE = True
except Exception as e:
    print(f"[secure_packager] Dilithium unavailable: {e}")
    PQCRYPTO_AVAILABLE = False
    dilithium_obj = None


def _dilithium_keypair_pk_sk(dil) -> Tuple[bytes, bytes]:
    """
    Generate a keypair for this Dilithium build.
    This build requires keygen(key_seed) and returns (pk_bytes, sk_bytes).
    """
    seed = os.urandom(64)  # 64-byte seed works with this build
    pair = dil.keygen(seed)
    if not (isinstance(pair, (tuple, list)) and len(pair) == 2):
        raise RuntimeError("Unexpected keygen output; expected (pk_bytes, sk_bytes).")
    pk, sk = pair
    if not isinstance(pk, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray)):
        raise RuntimeError("Keygen did not return raw bytes for (pk, sk).")
    return bytes(pk), bytes(sk)


def save_encrypted_file(
    plaintext: bytes,
    key_a_bits: List[int],
    original_filename: str = "file"
) -> bytes:
    """
    Encrypts the file and returns a secure JSON package (as bytes).
    Now: sensitive fields (file content, key_a_encoded, metadata) are inside the encrypted INTERNAL payload.
    The OUTER package only contains ciphertext, salt, and the post-quantum signature/public key.
    """
    # 1) Derive AES-256 key with salt using Key A
    key_with_salt = derive_aes_key_from_bits(key_a_bits)

    # 2) Build the INTERNAL payload (this will be encrypted)
    # INTERNAL payload only contains the encrypted file and minimal metadata.
    # Do NOT store raw Key A bits here — that would allow anyone with the
    # package to reconstruct the AES key. Key A must remain secret with Alice.
    # Note: We place `original_filename` in the OUTER package so it can be
    # included in AAD (authenticated but not encrypted). The INTERNAL payload
    # therefore omits filename to avoid duplication.
    # Compress plaintext before packaging to reduce ciphertext size
    if plaintext is None:
        plaintext = b""

    if ZSTD_AVAILABLE:
        cctx = zstd.ZstdCompressor(level=3)
        compressed = cctx.compress(plaintext)
        compression_used = "zstd"
    else:
        compressed = gzip.compress(plaintext, compresslevel=6)
        compression_used = "gzip"

    internal_payload = {
        "file_bytes_b64": base64.b64encode(compressed).decode("utf-8"),
        "compression": compression_used,
        "original_size": len(plaintext),
    }
    internal_bytes = json.dumps(internal_payload).encode("utf-8")

    # 3) Encrypt the entire INTERNAL payload
    # Use a package version string as AAD so outer-package version field
    # is bound into the authentication tag.
    version = "AES-GCM-v1"
    # 3.5) Build AAD from version, original filename and salt so it is
    # authenticated by AES-GCM but not encrypted. We expose `original_filename`
    # in the OUTER package (authenticated via signature and GCM AAD).
    salt_b64 = base64.b64encode(key_with_salt[32:]).decode("utf-8")
    aad_obj = {"version": version, "original_filename": original_filename, "salt": salt_b64}
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 4) Encrypt with AAD (binds metadata into the authentication tag)
    encrypted = aes_encrypt(internal_bytes, key_with_salt, aad=aad_bytes)

    # 5) OUTER package (NO sensitive fields exposed here except authenticated metadata)
    package = {
        "ciphertext": base64.b64encode(encrypted).decode("utf-8"),
        "salt": salt_b64,
        "version": version,
        "original_filename": original_filename,
        # <-- no key_a_encoded here anymore
    }

    # 5) Require post-quantum signature; fail early if not available
    if not PQCRYPTO_AVAILABLE:
        raise RuntimeError("Dilithium module not available — cannot sign the package.")

    # 6) Post-quantum signature (using this build's API)
    #    Generate (pk, sk) — order confirmed: (pk_bytes, sk_bytes)
    pk_bytes, sk_bytes = _dilithium_keypair_pk_sk(dilithium_obj)

    #    Sign the exact OUTER package bytes using sign_with_input(sk, message)
    package_bytes = json.dumps(package).encode("utf-8")
    signature = dilithium_obj.sign_with_input(sk_bytes, package_bytes)

    #    Attach signature and public key (base64)
    package["pq_signature"] = base64.b64encode(signature).decode("utf-8")
    package["pq_public_key"] = base64.b64encode(pk_bytes).decode("utf-8")

    # 7) Return the complete OUTER JSON package as bytes
    return json.dumps(package).encode("utf-8")


def load_and_decrypt_bytes(
    package_bytes: bytes,
    key_b_bits: List[int]
) -> Tuple[bytes, Dict[str, str], bool]:
    """
    Loads encrypted package and decrypts using derived key if valid.
    Validates post-quantum signature and key integrity before decrypting.
    
    Security Optimization: Verifies post-quantum signature BEFORE attempting decryption
    to prevent wasted computation on tampered packages.

    Returns:
        - Decrypted plaintext bytes
        - Metadata dict
        - Boolean indicating integrity success
    """
    # Parse OUTER package
    package = json.loads(package_bytes.decode("utf-8"))

    # ===== OPTIMIZATION: Verify signature FIRST (before expensive decryption) =====
    # 1) Verify post-quantum signature (if included)
    if PQCRYPTO_AVAILABLE and "pq_signature" in package and "pq_public_key" in package:
        pq_signature = base64.b64decode(package["pq_signature"])
        pq_public_key = base64.b64decode(package["pq_public_key"])

        # Rebuild OUTER package without signature fields for validation
        unsigned_package = {k: v for k, v in package.items() if k not in ("pq_signature", "pq_public_key")}
        unsigned_bytes = json.dumps(unsigned_package).encode("utf-8")

        try:
            # This build's verify order: verify(pk_bytes, message, sig_bytes)
            if not dilithium_obj.verify(pq_public_key, unsigned_bytes, pq_signature):
                # Signature invalid - reject immediately WITHOUT attempting decryption
                return b"", {}, False
        except Exception:
            # Signature verification failed - reject immediately
            return b"", {}, False
    else:
        # PQC available but no signature included -> invalid (reject before decryption)
        return b"", {}, False

    # 2) Extract OUTER encrypted components
    salt = base64.b64decode(package["salt"])
    ciphertext = base64.b64decode(package["ciphertext"])
    version = package.get("version", "")
    original_filename = package.get("original_filename", "decrypted_file")

    # 3) Derive AES key using Bob’s bits and the stored salt
    candidate_key = derive_aes_key_from_bits(key_b_bits, salt)

    # 4) Rebuild AAD the same way it was constructed during encryption
    aad_obj = {"version": version, "original_filename": original_filename, "salt": package["salt"]}
    aad_bytes = json.dumps(aad_obj, sort_keys=True).encode("utf-8")

    # 5) Decrypt the INTERNAL payload (pass AAD)
    # aes_decrypt will raise InvalidTag if authentication fails
    # This is now safe because we already verified the signature above
    internal_bytes = aes_decrypt(ciphertext, candidate_key, aad=aad_bytes)

    # 6) Parse INTERNAL payload (contains original file and protected fields)
    try:
        internal = json.loads(internal_bytes.decode("utf-8"))
    except Exception:
        return b"", {}, False

    # 6) Rehydrate original content (decompress after decoding)
    try:
        compressed_bytes = base64.b64decode(internal["file_bytes_b64"])
    except KeyError:
        return b"", {}, False

    # Decompress based on stored compression metadata
    compression_used = internal.get("compression", "")
    try:
        if compression_used == "zstd" and ZSTD_AVAILABLE:
            dctx = zstd.ZstdDecompressor()
            plaintext = dctx.decompress(compressed_bytes)
        elif compression_used == "gzip":
            plaintext = gzip.decompress(compressed_bytes)
        else:
            # Unknown or missing compression field — attempt zstd first, then raw
            if ZSTD_AVAILABLE:
                try:
                    dctx = zstd.ZstdDecompressor()
                    plaintext = dctx.decompress(compressed_bytes)
                except Exception:
                    # fallback to raw bytes
                    plaintext = compressed_bytes
            else:
                try:
                    plaintext = gzip.decompress(compressed_bytes)
                except Exception:
                    plaintext = compressed_bytes
    except Exception:
        return b"", {}, False

    # 7) Metadata (extracted from INTERNAL payload if stored)
    metadata = {
        "original_filename": internal.get("original_filename", "decrypted_file"),
        "extension": internal.get("extension", "bin"),
    }

    # Success: signature verified first, then AEAD authentication passed
    return plaintext, metadata, True
