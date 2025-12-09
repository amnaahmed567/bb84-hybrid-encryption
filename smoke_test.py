"""
Simple smoke test: encrypt then decrypt a small payload using the controller
Run: python smoke_test.py
"""

from bb84_backend.logic.controller import encrypt_file_local, decrypt_file_local

try:
    print("Starting smoke test: encrypt -> decrypt")
    b64, keyb = encrypt_file_local(b"hello world", "hello.txt")
    print("Encrypted (base64) length:", len(b64))
    print("Key B length (bits):", len(keyb))

    key_bits = [int(c) for c in keyb]
    decrypted, metadata = decrypt_file_local(b64, key_bits)

    if decrypted is None:
        print("Decryption failed; metadata:", metadata)
    else:
        print("Decrypted bytes:", decrypted)
        print("Metadata:", metadata)

except Exception as e:
    print("Smoke test error:", e)
