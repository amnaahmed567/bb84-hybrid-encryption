# ChaCha20-Poly1305 Implementation Guide

## Overview

This document describes the ChaCha20-Poly1305 implementation added to the BB84 hybrid quantum encryption system. ChaCha20-Poly1305 is now available as an alternative to AES-GCM for symmetric encryption.

---

## 🎯 What Was Added

### New Files Created:

1. **`bb84_backend/core/chacha20_engine.py`**
   - ChaCha20-Poly1305 AEAD encryption/decryption engine
   - Drop-in replacement for `aes_engine.py`
   - Same API: `chacha20_encrypt()` and `chacha20_decrypt()`

2. **`bb84_backend/secure_io/secure_packager_chacha20.py`**
   - Complete packaging with ChaCha20-Poly1305
   - Mirrors `secure_packager.py` but uses ChaCha20
   - Functions: `save_encrypted_file_chacha20()` and `load_and_decrypt_bytes_chacha20()`

### Modified Files:

1. **`bb84_backend/core/key_utils.py`**
   - Added `derive_chacha20_key_from_bits()` function
   - Uses HKDF with info=`"bb84-chacha20-encryption-key"` for key separation

2. **`bb84_backend/logic/controller.py`**
   - Added `cipher` parameter to `encrypt_file_local()` and `decrypt_file_local()`
   - Auto-detects cipher from package version field
   - Supports both AES-GCM and ChaCha20 side-by-side

3. **`bb84_backend/core/__init__.py`** and **`bb84_backend/secure_io/__init__.py`**
   - Updated to export ChaCha20 functions

---

## 🔐 Security Properties

### ChaCha20-Poly1305 Guarantees:

✅ **256-bit key size** (quantum-resistant for decades)  
✅ **AEAD** (Authenticated Encryption with Associated Data)  
✅ **Poly1305 MAC** (128-bit authentication tag)  
✅ **96-bit nonce** (12 bytes, randomly generated per encryption)  
✅ **Stream cipher** (constant-time, no cache timing attacks)  
✅ **Post-quantum signatures** (Dilithium5, same as AES-GCM)  
✅ **Metadata authentication** (AAD includes version, filename, salt)  
✅ **Verify-before-decrypt** (signature checked first)  

### Equivalent to AES-GCM:

Both ChaCha20-Poly1305 and AES-256-GCM provide:
- 256-bit encryption strength
- AEAD authentication (confidentiality + integrity)
- Quantum resistance (for decades with current tech)
- Post-quantum signature protection (Dilithium5)

---

## 📊 Performance Comparison

### Hardware WITH AES-NI (Modern Intel/AMD CPUs):
- **AES-GCM:** ~2-5 GB/s (hardware-accelerated) ⚡
- **ChaCha20:** ~500 MB/s (software-only)
- **Winner:** AES-GCM (4-10x faster)

### Hardware WITHOUT AES-NI (ARM, Mobile, Older CPUs):
- **AES-GCM:** ~50-100 MB/s (software-only, slow)
- **ChaCha20:** ~500-800 MB/s (optimized software) ⚡
- **Winner:** ChaCha20 (5-15x faster)

### Recommendation:
- **Use AES-GCM** on modern x86/x64 servers/desktops (default)
- **Use ChaCha20** on ARM devices, mobile, Raspberry Pi, or legacy systems

---

## 🚀 Usage Examples

### 1. Encrypting with ChaCha20

```python
from bb84_backend.logic.controller import encrypt_file_local

# Read file
with open("secret.txt", "rb") as f:
    plaintext = f.read()

# Encrypt with ChaCha20-Poly1305
encrypted_b64, key_b_str = encrypt_file_local(
    data=plaintext,
    filename="secret.txt",
    cipher="ChaCha20"  # <-- Use ChaCha20 instead of AES-GCM
)

# Save encrypted file
with open("secret.bb84", "w") as f:
    f.write(encrypted_b64)

# Save Key B for receiver
with open("Key_B.txt", "w") as f:
    f.write(key_b_str)

print("✓ Encrypted with ChaCha20-Poly1305")
```

### 2. Decrypting ChaCha20 Files

```python
from bb84_backend.logic.controller import decrypt_file_local

# Load encrypted file
with open("secret.bb84", "r") as f:
    encrypted_b64 = f.read()

# Load Key B
with open("Key_B.txt", "r") as f:
    key_b_str = f.read().strip()
    key_b_bits = [int(b) for b in key_b_str]

# Decrypt (auto-detects ChaCha20 from package)
plaintext, metadata = decrypt_file_local(
    data_base64=encrypted_b64,
    key_b_bits=key_b_bits,
    cipher="auto"  # <-- Auto-detects cipher from package version
)

if plaintext:
    # Save decrypted file
    filename = metadata.get("original_filename", "decrypted_file")
    with open(filename, "wb") as f:
        f.write(plaintext)
    print(f"✓ Decrypted: {filename}")
else:
    print(f"✗ Decryption failed: {metadata.get('error', 'Unknown error')}")
```

### 3. Direct API Usage (Low-Level)

```python
from bb84_backend.core.chacha20_engine import chacha20_encrypt, chacha20_decrypt
from bb84_backend.core.key_utils import derive_chacha20_key_from_bits

# Generate quantum key (BB84)
from bb84_backend.core.bb84_quantum import bb84_protocol
key_a_bits, key_b_bits, _ = bb84_protocol(length=256)

# Derive ChaCha20 key
key_with_salt = derive_chacha20_key_from_bits(key_a_bits)

# Encrypt with metadata
plaintext = b"Secret quantum message"
aad = b'{"version": "ChaCha20-v1", "filename": "test.txt"}'
encrypted = chacha20_encrypt(plaintext, key_with_salt, aad=aad)

# Decrypt
decrypted = chacha20_decrypt(encrypted, key_with_salt, aad=aad)
assert decrypted == plaintext
print("✓ Direct ChaCha20 encryption/decryption successful")
```

---

## 🔄 Cipher Selection Logic

### Automatic Detection (Recommended):

```python
# Decryption auto-detects cipher from package version field
plaintext, metadata = decrypt_file_local(encrypted, key_b_bits, cipher="auto")
```

The system reads the `version` field in the JSON package:
- `"AES-GCM-v1"` → Uses AES-256-GCM
- `"ChaCha20-v1"` → Uses ChaCha20-Poly1305

### Manual Selection:

```python
# Force AES-GCM encryption
encrypted, key_b = encrypt_file_local(data, filename, cipher="AES-GCM")

# Force ChaCha20 encryption
encrypted, key_b = encrypt_file_local(data, filename, cipher="ChaCha20")

# Force AES-GCM decryption (ignore package version)
plaintext, metadata = decrypt_file_local(encrypted, key_b_bits, cipher="AES-GCM")

# Force ChaCha20 decryption
plaintext, metadata = decrypt_file_local(encrypted, key_b_bits, cipher="ChaCha20")
```

---

## 📦 Package Format

### ChaCha20 Package Structure:

```json
{
  "ciphertext": "<base64: nonce(12) + ciphertext + poly1305_tag(16)>",
  "salt": "<base64: 16-byte HKDF salt>",
  "version": "ChaCha20-v1",
  "original_filename": "secret.txt",
  "pq_signature": "<base64: Dilithium5 signature>",
  "pq_public_key": "<base64: Dilithium5 public key>"
}
```

### Differences from AES-GCM Package:

| Field | AES-GCM | ChaCha20 |
|-------|---------|----------|
| `version` | `"AES-GCM-v1"` | `"ChaCha20-v1"` |
| `ciphertext` structure | nonce(12) + ct + GCM_tag(16) | nonce(12) + ct + Poly1305_tag(16) |
| Key derivation info | `"bb84-aes-key-derivation"` | `"bb84-chacha20-encryption-key"` |

Everything else (signatures, AAD, metadata) is identical.

---

## 🔑 Key Derivation

### AES-GCM Key Derivation:

```python
from bb84_backend.core.key_utils import derive_aes_key_from_bits

key_with_salt = derive_aes_key_from_bits(quantum_bits)
# HKDF-SHA256 with info="bb84-aes-key-derivation"
```

### ChaCha20 Key Derivation:

```python
from bb84_backend.core.key_utils import derive_chacha20_key_from_bits

key_with_salt = derive_chacha20_key_from_bits(quantum_bits)
# HKDF-SHA256 with info="bb84-chacha20-encryption-key"
```

### Key Separation:

Using different `info` parameters ensures:
- AES keys and ChaCha20 keys are cryptographically independent
- No key reuse between ciphers (defense-in-depth)
- Each cipher has its own namespace

---

## 🧪 Testing

### Test 1: ChaCha20 Encryption/Decryption

```python
from bb84_backend.core.chacha20_engine import chacha20_encrypt, chacha20_decrypt
import os

# Generate random key
key = os.urandom(32)
salt = os.urandom(16)
key_with_salt = key + salt

# Test data
plaintext = b"Test message for ChaCha20-Poly1305"
aad = b'{"version": "test"}'

# Encrypt
ciphertext = chacha20_encrypt(plaintext, key_with_salt, aad=aad)
print(f"Ciphertext length: {len(ciphertext)} bytes")
print(f"  - Nonce: 12 bytes")
print(f"  - Encrypted: {len(plaintext)} bytes")
print(f"  - Tag: 16 bytes")

# Decrypt
decrypted = chacha20_decrypt(ciphertext, key_with_salt, aad=aad)
assert decrypted == plaintext
print("✓ ChaCha20 encryption/decryption passed")
```

### Test 2: Full BB84 Flow with ChaCha20

```python
from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local

# Encrypt
plaintext = b"Quantum-safe encrypted message"
encrypted_b64, key_b_str = encrypt_file_local(plaintext, "test.txt", cipher="ChaCha20")

# Convert Key B to bits
key_b_bits = [int(b) for b in key_b_str]

# Decrypt
decrypted, metadata = decrypt_file_local(encrypted_b64, key_b_bits, cipher="auto")

assert decrypted == plaintext
assert metadata["original_filename"] == "test.txt"
print("✓ Full BB84 + ChaCha20 flow passed")
```

### Test 3: Tamper Detection

```python
from cryptography.exceptions import InvalidTag

# Encrypt valid data
encrypted_b64, key_b_str = encrypt_file_local(b"test", "test.txt", cipher="ChaCha20")
key_b_bits = [int(b) for b in key_b_str]

# Tamper with ciphertext
import base64
encrypted_bytes = base64.b64decode(encrypted_b64)
tampered = encrypted_bytes[:-10] + b"TAMPERED!!"
tampered_b64 = base64.b64encode(tampered).decode()

# Attempt decryption (should fail)
decrypted, metadata = decrypt_file_local(tampered_b64, key_b_bits, cipher="auto")

assert decrypted is None
assert "error" in metadata
print("✓ Tamper detection working (Poly1305 authentication)")
```

### Test 4: Wrong Key Rejection

```python
# Encrypt with Key A
encrypted_b64, key_b_str = encrypt_file_local(b"test", "test.txt", cipher="ChaCha20")

# Try decrypting with wrong key
wrong_key_bits = [1] * len(key_b_str)  # All 1s (wrong key)
decrypted, metadata = decrypt_file_local(encrypted_b64, wrong_key_bits, cipher="auto")

assert decrypted is None
assert "error" in metadata
print("✓ Wrong key rejection working")
```

---

## 📝 Metrics Collection

The system automatically logs ChaCha20 usage in `bb84_metrics.json`:

```json
{
  "Cipher Algorithm": "ChaCha20",
  "Encryption Time (s)": 0.0234,
  "Original File Size (bytes)": 1024,
  "Encrypted File Size (bytes)": 1156,
  "Key Confirmation": "Passed",
  "AEAD Authentication": "Passed",
  "Post-Quantum Signature": "Enabled",
  "Timestamp": "2025-12-09 10:30:45.123456"
}
```

---

## 🛡️ Security Checklist

| Feature | AES-GCM | ChaCha20 | Status |
|---------|---------|----------|--------|
| **BB84 Key Distribution** | ✅ | ✅ | Identical |
| **Key Confirmation** | ✅ | ✅ | Identical (20-bit sample) |
| **HKDF Key Derivation** | ✅ | ✅ | Separate info params |
| **256-bit Encryption** | ✅ | ✅ | Both quantum-resistant |
| **AEAD Authentication** | ✅ GCM | ✅ Poly1305 | Equivalent |
| **Metadata in AAD** | ✅ | ✅ | Identical |
| **Post-Quantum Signatures** | ✅ Dilithium5 | ✅ Dilithium5 | Identical |
| **Verify-Before-Decrypt** | ✅ | ✅ | Identical optimization |
| **Nonce Uniqueness** | ✅ Random | ✅ Random | Both 12-byte nonces |
| **Timing Attack Resistance** | ⚠️ Cache-based | ✅ Constant-time | ChaCha20 better |

---

## 🔧 Integration with GUI

To add ChaCha20 selection to the GUI (`gui/bb84_gui.py`):

```python
# Add cipher selection dropdown
self.cipher_choice = ttk.Combobox(
    self.encrypt_frame,
    values=["AES-GCM (Fast on x86/x64)", "ChaCha20 (Fast on ARM/Mobile)"],
    state="readonly"
)
self.cipher_choice.current(0)  # Default to AES-GCM
self.cipher_choice.pack(pady=5)

# In encrypt button handler:
cipher = "ChaCha20" if "ChaCha20" in self.cipher_choice.get() else "AES-GCM"
encrypted_b64, key_b_str = encrypt_file_local(data, filename, cipher=cipher)
```

---

## 🎓 Educational Notes

### Why ChaCha20-Poly1305?

1. **Software Performance:** ChaCha20 is optimized for CPUs without AES-NI hardware
2. **Constant-Time:** Resistant to cache-timing attacks (no lookup tables)
3. **Mobile-Friendly:** Excellent performance on ARM processors
4. **TLS 1.3:** Approved cipher suite (Google uses it for mobile Chrome)
5. **IETF Standard:** RFC 8439 (ChaCha20-Poly1305 AEAD)

### Why Keep AES-GCM?

1. **Hardware Acceleration:** 4-10x faster on modern CPUs with AES-NI
2. **Industry Standard:** Most widely deployed AEAD cipher
3. **NIST Approved:** FIPS 140-2 approved (required for government)
4. **Backward Compatibility:** Existing encrypted files use AES-GCM

### Best of Both Worlds:

This implementation lets you choose the optimal cipher per platform:
- **Desktop/Server:** AES-GCM (hardware-accelerated)
- **Mobile/Embedded:** ChaCha20 (software-optimized)
- **Unknown:** Auto-detect from package version

---

## ✅ Summary

### What You Can Do Now:

1. ✅ Encrypt files with ChaCha20-Poly1305 (alternative to AES-GCM)
2. ✅ Decrypt files encrypted with either cipher
3. ✅ Auto-detect cipher from package version
4. ✅ Use same BB84 quantum key for both ciphers
5. ✅ Get identical security guarantees (AEAD + post-quantum signatures)
6. ✅ Choose optimal cipher per platform (hardware vs software)

### API Summary:

```python
# High-level API (recommended)
from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local

encrypted, key_b = encrypt_file_local(data, filename, cipher="ChaCha20")
plaintext, metadata = decrypt_file_local(encrypted, key_b_bits, cipher="auto")

# Low-level API (advanced)
from bb84_backend.core.chacha20_engine import chacha20_encrypt, chacha20_decrypt
from bb84_backend.core.key_utils import derive_chacha20_key_from_bits
from bb84_backend.secure_io.secure_packager_chacha20 import (
    save_encrypted_file_chacha20,
    load_and_decrypt_bytes_chacha20
)
```

---

**Last Updated:** December 9, 2025  
**Implementation:** Production-ready ✅  
**Security:** Military-grade AEAD + Post-Quantum Signatures 🔐
