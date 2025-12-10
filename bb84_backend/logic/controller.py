import os
import sys
import base64
import hashlib
import time
from datetime import datetime
from collections import Counter
from math import log2
from typing import Tuple, Optional, List
import json
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


# Add core modules path for relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import core cryptographic modules
from core.bb84_quantum import bb84_protocol, sample_key_confirmation
from core.key_utils import derive_aes_key_from_bits, derive_chacha20_key_from_bits
from core.encryption import encrypt_file_local as core_encrypt_file_local
from secure_io.secure_packager import save_encrypted_file, load_and_decrypt_bytes
from secure_io.secure_packager_chacha20 import save_encrypted_file_chacha20, load_and_decrypt_bytes_chacha20
from cryptography.exceptions import InvalidTag

# Metrics collector for BB84 encryption/decryption process
class BB84MetricsCollector:
    def __init__(self):
        self.metrics = {}
        self.start_time = None

    # Start timing an operation
    def start_timer(self):
        self.start_time = time.perf_counter()

    # Stop timing and record the elapsed duration
    def stop_timer(self, label="Encryption Time (s)"):
        if self.start_time:
            elapsed = time.perf_counter() - self.start_time
            self.metrics[label] = round(elapsed, 4)

    # Log the current UTC timestamp
    def add_timestamp(self):
        self.metrics["Timestamp"] = str(datetime.utcnow())

    # Add BB84 key properties and entropy estimation
    def add_key_metrics(self, key_a_bits, key_b_bits):
        self.metrics["Key A Length"] = len(key_a_bits)
        self.metrics["Key B Length"] = len(key_b_bits)
        self.metrics["Key B - Count of 1s"] = key_b_bits.count(1)
        self.metrics["Key B - Count of 0s"] = key_b_bits.count(0)

        matches = sum(1 for a, b in zip(key_a_bits, key_b_bits) if a == b)
        percentage = 100 * matches / len(key_b_bits)
        self.metrics["A/B Bit Match Percentage"] = round(percentage, 2)

        # Estimate Shannon entropy from key A
        total = len(key_a_bits)
        counts = Counter(key_a_bits)
        entropy = -sum((c / total) * log2(c / total) for c in counts.values())
        self.metrics["Estimated Shannon Entropy"] = round(entropy, 4)

    # Record original file size
    def add_file_size_before_encryption(self, original_bytes: bytes):
        self.metrics["Original File Size (bytes)"] = len(original_bytes)

    # Record size of the encrypted file
    def add_file_size_after_encryption(self, encrypted_bytes: bytes):
        self.metrics["Encrypted File Size (bytes)"] = len(encrypted_bytes)

    # Record size of the decrypted output file
    def add_decrypted_file_size(self, decrypted_bytes: bytes):
        self.metrics["Decrypted File Size (bytes)"] = len(decrypted_bytes)

    # Save SHA-256 hash of encrypted content
    def add_sha256_hash(self, cipher_bytes):
        self.metrics["SHA-256 Hash of Encrypted File"] = hashlib.sha256(cipher_bytes).hexdigest()

    # Save SHA-256 hash of decrypted output
    def add_sha256_of_decrypted(self, decrypted_bytes):
        self.metrics["SHA-256 Hash of Decrypted File"] = hashlib.sha256(decrypted_bytes).hexdigest()

    # Register result of HMAC integrity check
    def add_aead_authentication(self, valid):
        # Record result of AEAD authentication (AES-GCM)
        self.metrics["AEAD Authentication"] = "Passed" if valid else "Failed"
    
    # Record key confirmation (sacrifice/sample) result
    def add_key_confirmation(self, passed: bool, error_rate: float):
        self.metrics["Key Confirmation"] = "Passed" if passed else "Failed"
        self.metrics["Key Confirmation Error Rate"] = round(error_rate, 4)

    # Log whether post-quantum signature was used
    def add_quantum_signature_status(self, enabled: bool):
        self.metrics["Post-Quantum Signature"] = "Enabled" if enabled else "Disabled"
    
    # Record encryption cipher used (AES-GCM or ChaCha20-Poly1305)
    def add_cipher_type(self, cipher: str):
        self.metrics["Cipher Algorithm"] = cipher

    # Export all collected metrics to a JSON file
    def export_to_json(self, output_path="bb84_metrics.json"):
        with open(output_path, "w") as f:
            json.dump(self.metrics, f, indent=2)
        return output_path

# ENCRYPTION LOGIC (enhanced with full metrics collection)
def encrypt_file_local(data: bytes, filename: str, cipher: str = "AES-GCM") -> Tuple[str, str]:
    """
    Encrypts a file using BB84 quantum key distribution and symmetric AEAD encryption.
    
    Args:
        data: Raw file bytes to encrypt
        filename: Original filename for metadata
        cipher: Encryption algorithm choice:
                - "AES-GCM" (default): AES-256-GCM (best on modern CPUs with AES-NI)
                - "ChaCha20": ChaCha20-Poly1305 (best on ARM/mobile or without AES-NI)
    
    Returns:
        Tuple of:
        - encrypted_b64 (str): Base64-encoded encrypted package
        - key_b_str (str): Key B as binary string (to be transmitted to receiver)
    
    Security:
        - BB84 quantum key distribution (256 bits)
        - Key confirmation via sample (20 bits sacrificed, 15% error threshold)
        - HKDF-SHA256 key derivation
        - AEAD encryption (AES-GCM or ChaCha20-Poly1305)
        - Dilithium5 post-quantum signatures
        - Metadata authentication (AAD)
    
    Example:
        >>> plaintext = b"Secret document"
        >>> # Use AES-GCM (default, best on x86/x64 with AES-NI)
        >>> encrypted, key_b = encrypt_file_local(plaintext, "secret.txt")
        >>> 
        >>> # Or use ChaCha20 (best on ARM/mobile)
        >>> encrypted, key_b = encrypt_file_local(plaintext, "secret.txt", cipher="ChaCha20")
    """
    # Initialize metrics collection
    metrics = BB84MetricsCollector()
    metrics.start_timer()
    metrics.add_timestamp()
    metrics.add_file_size_before_encryption(data)
    metrics.add_cipher_type(cipher)
    
    # Generate BB84 quantum key and optional post-quantum signature
    key_a_bits, key_b_bits, signature = bb84_protocol(length=256, authenticate=True)
    
    # Perform BB84 key confirmation (sacrifice/sample check)
    passed, error_rate, key_a_bits_remain, key_b_bits_remain, sampled = sample_key_confirmation(
        key_a_bits, key_b_bits, sample_size=20, threshold=0.15
    )
    
    # Record key confirmation result
    metrics.add_key_confirmation(passed, error_rate)
    
    if not passed:
        # Abort encryption due to high error rate (possible eavesdropping)
        metrics.stop_timer("Encryption Time (s)")
        metrics.export_to_json("bb84_metrics.json")
        return "", f"ERROR: High error rate detected ({error_rate:.2%}). Possible eavesdropping. Encryption aborted."
    
    # Use remaining keys after sample check
    key_a_bits = key_a_bits_remain
    key_b_bits = key_b_bits_remain
    
    # Package and encrypt the data using selected cipher
    if cipher.upper() == "CHACHA20":
        package_bytes = save_encrypted_file_chacha20(
            plaintext=data,
            key_a_bits=key_a_bits,
            original_filename=filename
        )
    else:  # Default to AES-GCM
        package_bytes = save_encrypted_file(
            plaintext=data,
            key_a_bits=key_a_bits,
            original_filename=filename
        )
    
    # Record encryption performance and key stats
    metrics.stop_timer("Encryption Time (s)")
    metrics.add_key_metrics(key_a_bits, key_b_bits)
    metrics.add_file_size_after_encryption(package_bytes)
    metrics.add_sha256_hash(package_bytes)
    metrics.add_quantum_signature_status(signature is not None)
    metrics.export_to_json("bb84_metrics.json")
    
    # Convert encrypted output to Base64 and format Key B as string
    encrypted_b64 = base64.b64encode(package_bytes).decode("utf-8")
    key_b_str = "".join(map(str, key_b_bits))
    return encrypted_b64, key_b_str

# DECRYPTION LOGIC (includes full metrics logging)
def decrypt_file_local(data_base64: str, key_b_bits: List[int], cipher: str = "auto") -> Tuple[Optional[bytes], Optional[dict]]:
    """
    Decrypts a file encrypted with BB84 quantum encryption.
    
    Args:
        data_base64: Base64-encoded encrypted package
        key_b_bits: Bob's quantum key bits (from BB84 protocol)
        cipher: Decryption algorithm choice:
                - "auto" (default): Automatically detect from package version field
                - "AES-GCM": Force AES-256-GCM decryption
                - "ChaCha20": Force ChaCha20-Poly1305 decryption
    
    Returns:
        Tuple of:
        - data (bytes): Decrypted plaintext (None if failed)
        - metadata (dict): Original filename and error messages (if any)
    
    Security Checks:
        1. Dilithium5 signature verification (verify-before-decrypt optimization)
        2. AEAD authentication (GCM or Poly1305 tag verification)
        3. AAD verification (metadata tampering detection)
        4. Key confirmation (implicit via successful decryption)
    
    Example:
        >>> # Auto-detect cipher from package
        >>> plaintext, metadata = decrypt_file_local(encrypted, key_b_bits)
        >>> if plaintext:
        ...     print(f"Decrypted: {metadata['original_filename']}")
        ... else:
        ...     print(f"Failed: {metadata['error']}")
    """
    # Initialize metrics
    metrics = BB84MetricsCollector()
    metrics.start_timer()
    metrics.add_timestamp()

    # Decode Base64
    encrypted_bytes = base64.b64decode(data_base64)
    
    # Auto-detect cipher from package version if not specified
    if cipher.lower() == "auto":
        try:
            package = json.loads(encrypted_bytes.decode("utf-8"))
            version = package.get("version", "")
            if "ChaCha20" in version:
                cipher = "ChaCha20"
            else:
                cipher = "AES-GCM"
        except Exception:
            cipher = "AES-GCM"  # Default to AES-GCM if detection fails
    
    metrics.add_cipher_type(cipher)
    
    # Attempt decryption with appropriate cipher
    try:
        if cipher.upper() == "CHACHA20":
            data, metadata, integrity_ok = load_and_decrypt_bytes_chacha20(encrypted_bytes, key_b_bits)
        else:  # AES-GCM
            data, metadata, integrity_ok = load_and_decrypt_bytes(encrypted_bytes, key_b_bits)
    except InvalidTag:
        # Authentication failed — record AEAD failure and return clear message
        metrics.stop_timer("Decryption Time (s)")
        metrics.add_aead_authentication(False)
        metrics.add_sha256_hash(encrypted_bytes)
        metrics.export_to_json("bb84_metrics.json")
        return None, {"error": "Authentication failed: ciphertext/tag mismatch (possible wrong Key B or tampered file)."}

    # Log decryption time and integrity (AEAD) verification status
    metrics.stop_timer("Decryption Time (s)")
    metrics.add_aead_authentication(integrity_ok)
    metrics.add_sha256_hash(encrypted_bytes)

    if data:
        metrics.add_decrypted_file_size(data)
        metrics.add_sha256_of_decrypted(data)

    metrics.export_to_json("bb84_metrics.json")

    if not integrity_ok:
        return None, {"error": "Key B does not match the original quantum key. Integrity verification failed."}

    return data, metadata
