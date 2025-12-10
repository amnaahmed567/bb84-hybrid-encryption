#!/usr/bin/env python3
"""
ChaCha20-Poly1305 Test Suite
Tests the new ChaCha20 encryption alongside AES-GCM
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local
from bb84_backend.core.chacha20_engine import chacha20_encrypt, chacha20_decrypt
from bb84_backend.core.key_utils import derive_chacha20_key_from_bits
import time


def test_1_basic_chacha20_encryption():
    """Test 1: Basic ChaCha20 encryption/decryption"""
    print("\n" + "="*70)
    print("TEST 1: Basic ChaCha20-Poly1305 Encryption/Decryption")
    print("="*70)
    
    # Test data
    plaintext = b"This is a secret quantum message encrypted with ChaCha20-Poly1305!"
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Length: {len(plaintext)} bytes")
    
    # Generate random key
    key = os.urandom(32)
    salt = os.urandom(16)
    key_with_salt = key + salt
    aad = b'{"version": "test", "filename": "test.txt"}'
    
    # Encrypt
    print("\n[Encrypting...]")
    start = time.time()
    ciphertext = chacha20_encrypt(plaintext, key_with_salt, aad=aad)
    encrypt_time = time.time() - start
    
    print(f"✓ Encrypted in {encrypt_time*1000:.2f} ms")
    print(f"  Ciphertext length: {len(ciphertext)} bytes")
    print(f"    - Nonce: 12 bytes")
    print(f"    - Encrypted data: {len(plaintext)} bytes")
    print(f"    - Poly1305 tag: 16 bytes")
    
    # Decrypt
    print("\n[Decrypting...]")
    start = time.time()
    decrypted = chacha20_decrypt(ciphertext, key_with_salt, aad=aad)
    decrypt_time = time.time() - start
    
    print(f"✓ Decrypted in {decrypt_time*1000:.2f} ms")
    print(f"  Decrypted: {decrypted.decode()}")
    
    # Verify
    assert decrypted == plaintext, "Decryption failed!"
    print("\n✅ TEST 1 PASSED: Basic encryption/decryption successful")


def test_2_full_bb84_chacha20_flow():
    """Test 2: Full BB84 + ChaCha20 flow"""
    print("\n" + "="*70)
    print("TEST 2: Full BB84 Quantum Key Distribution + ChaCha20")
    print("="*70)
    
    plaintext = b"Top secret file encrypted with BB84 quantum keys and ChaCha20!"
    filename = "secret_quantum_file.txt"
    
    print(f"Original file: {filename}")
    print(f"Size: {len(plaintext)} bytes")
    
    # Encrypt with ChaCha20
    print("\n[Encrypting with BB84 + ChaCha20...]")
    start = time.time()
    encrypted_b64, key_b_str = encrypt_file_local(plaintext, filename, cipher="ChaCha20")
    encrypt_time = time.time() - start
    
    print(f"✓ Encryption completed in {encrypt_time*1000:.2f} ms")
    print(f"  Key B length: {len(key_b_str)} bits")
    print(f"  Encrypted package size: {len(encrypted_b64)} bytes (base64)")
    
    # Convert Key B to bits
    key_b_bits = [int(b) for b in key_b_str]
    
    # Decrypt (auto-detect ChaCha20)
    print("\n[Decrypting with auto-detection...]")
    start = time.time()
    decrypted, metadata = decrypt_file_local(encrypted_b64, key_b_bits, cipher="auto")
    decrypt_time = time.time() - start
    
    print(f"✓ Decryption completed in {decrypt_time*1000:.2f} ms")
    print(f"  Original filename: {metadata.get('original_filename', 'N/A')}")
    print(f"  Decrypted size: {len(decrypted)} bytes")
    
    # Verify
    assert decrypted == plaintext, "Decryption failed!"
    assert metadata["original_filename"] == filename, "Metadata mismatch!"
    
    print("\n✅ TEST 2 PASSED: Full BB84 + ChaCha20 flow successful")


def test_3_aes_vs_chacha20_comparison():
    """Test 3: Compare AES-GCM vs ChaCha20 side-by-side"""
    print("\n" + "="*70)
    print("TEST 3: AES-GCM vs ChaCha20-Poly1305 Comparison")
    print("="*70)
    
    # Test data (1 KB)
    plaintext = b"X" * 1024
    filename = "test_1kb.bin"
    
    print(f"Test file size: {len(plaintext)} bytes")
    
    # Test AES-GCM
    print("\n[Testing AES-GCM...]")
    start = time.time()
    aes_encrypted, aes_key_b = encrypt_file_local(plaintext, filename, cipher="AES-GCM")
    aes_encrypt_time = time.time() - start
    
    aes_key_bits = [int(b) for b in aes_key_b]
    start = time.time()
    aes_decrypted, _ = decrypt_file_local(aes_encrypted, aes_key_bits, cipher="AES-GCM")
    aes_decrypt_time = time.time() - start
    
    print(f"  Encryption: {aes_encrypt_time*1000:.2f} ms")
    print(f"  Decryption: {aes_decrypt_time*1000:.2f} ms")
    print(f"  Package size: {len(aes_encrypted)} bytes")
    
    # Test ChaCha20
    print("\n[Testing ChaCha20...]")
    start = time.time()
    chacha_encrypted, chacha_key_b = encrypt_file_local(plaintext, filename, cipher="ChaCha20")
    chacha_encrypt_time = time.time() - start
    
    chacha_key_bits = [int(b) for b in chacha_key_b]
    start = time.time()
    chacha_decrypted, _ = decrypt_file_local(chacha_encrypted, chacha_key_bits, cipher="ChaCha20")
    chacha_decrypt_time = time.time() - start
    
    print(f"  Encryption: {chacha_encrypt_time*1000:.2f} ms")
    print(f"  Decryption: {chacha_decrypt_time*1000:.2f} ms")
    print(f"  Package size: {len(chacha_encrypted)} bytes")
    
    # Compare
    print("\n[Performance Comparison]")
    print(f"  Encryption speed ratio: {aes_encrypt_time/chacha_encrypt_time:.2f}x")
    print(f"  Decryption speed ratio: {aes_decrypt_time/chacha_decrypt_time:.2f}x")
    print(f"  (Ratio > 1.0 means ChaCha20 is faster)")
    
    # Verify both work
    assert aes_decrypted == plaintext, "AES decryption failed!"
    assert chacha_decrypted == plaintext, "ChaCha20 decryption failed!"
    
    print("\n✅ TEST 3 PASSED: Both ciphers working correctly")


def test_4_tamper_detection():
    """Test 4: Tamper detection with ChaCha20"""
    print("\n" + "="*70)
    print("TEST 4: Tamper Detection (Poly1305 Authentication)")
    print("="*70)
    
    plaintext = b"Tamper detection test"
    filename = "test.txt"
    
    # Encrypt
    print("\n[Encrypting...]")
    encrypted_b64, key_b_str = encrypt_file_local(plaintext, filename, cipher="ChaCha20")
    key_b_bits = [int(b) for b in key_b_str]
    print("✓ Encryption successful")
    
    # Test 1: Valid decryption
    print("\n[Test 4.1: Valid decryption]")
    decrypted, metadata = decrypt_file_local(encrypted_b64, key_b_bits, cipher="auto")
    assert decrypted == plaintext, "Valid decryption failed!"
    print("✓ Valid decryption successful")
    
    # Test 2: Tampered ciphertext
    print("\n[Test 4.2: Tampered ciphertext]")
    import base64
    encrypted_bytes = base64.b64decode(encrypted_b64)
    tampered = encrypted_bytes[:-10] + b"TAMPERED!!"
    tampered_b64 = base64.b64encode(tampered).decode()
    
    decrypted, metadata = decrypt_file_local(tampered_b64, key_b_bits, cipher="auto")
    assert decrypted is None, "Tamper detection failed!"
    assert "error" in metadata, "Error not reported!"
    print("✓ Tampered data rejected (Poly1305 authentication working)")
    
    # Test 3: Wrong key
    print("\n[Test 4.3: Wrong decryption key]")
    wrong_key_bits = [1 if b == 0 else 0 for b in key_b_bits]  # Flip all bits
    decrypted, metadata = decrypt_file_local(encrypted_b64, wrong_key_bits, cipher="auto")
    assert decrypted is None, "Wrong key not detected!"
    assert "error" in metadata, "Error not reported!"
    print("✓ Wrong key rejected")
    
    print("\n✅ TEST 4 PASSED: All tamper detection tests successful")


def test_5_auto_cipher_detection():
    """Test 5: Auto-detect cipher from package"""
    print("\n" + "="*70)
    print("TEST 5: Automatic Cipher Detection")
    print("="*70)
    
    plaintext = b"Auto-detection test"
    filename = "test.txt"
    
    # Encrypt with AES-GCM
    print("\n[Encrypting with AES-GCM...]")
    aes_encrypted, aes_key_b = encrypt_file_local(plaintext, filename, cipher="AES-GCM")
    aes_key_bits = [int(b) for b in aes_key_b]
    
    # Decrypt with auto-detection
    print("[Decrypting with auto-detection...]")
    decrypted, metadata = decrypt_file_local(aes_encrypted, aes_key_bits, cipher="auto")
    assert decrypted == plaintext, "AES auto-detection failed!"
    print("✓ Auto-detected AES-GCM correctly")
    
    # Encrypt with ChaCha20
    print("\n[Encrypting with ChaCha20...]")
    chacha_encrypted, chacha_key_b = encrypt_file_local(plaintext, filename, cipher="ChaCha20")
    chacha_key_bits = [int(b) for b in chacha_key_b]
    
    # Decrypt with auto-detection
    print("[Decrypting with auto-detection...]")
    decrypted, metadata = decrypt_file_local(chacha_encrypted, chacha_key_bits, cipher="auto")
    assert decrypted == plaintext, "ChaCha20 auto-detection failed!"
    print("✓ Auto-detected ChaCha20 correctly")
    
    print("\n✅ TEST 5 PASSED: Auto-detection working for both ciphers")


def main():
    """Run all tests"""
    print("\n" + "🔐 "*20)
    print("ChaCha20-Poly1305 Implementation Test Suite")
    print("BB84 Quantum Encryption + ChaCha20/AES-GCM AEAD")
    print("🔐 "*20)
    
    tests = [
        test_1_basic_chacha20_encryption,
        test_2_full_bb84_chacha20_flow,
        test_3_aes_vs_chacha20_comparison,
        test_4_tamper_detection,
        test_5_auto_cipher_detection,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ TEST FAILED: {test_func.__name__}")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total tests: {passed + failed}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! ChaCha20 implementation ready for production.")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review errors above.")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
