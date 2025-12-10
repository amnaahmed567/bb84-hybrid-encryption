# 🖥️ GUI Usage Guide - ChaCha20 Cipher Selection

## ✅ GUI is Now Running!

The BB84 Quantum Encryption GUI now includes **ChaCha20-Poly1305** cipher selection alongside AES-GCM.

---

## 🎯 How to Use the GUI

### 📤 **Encrypting a File:**

1. **Select Mode:** Choose "Encrypt" radio button (default)

2. **Choose Cipher Algorithm:**
   - **AES-GCM** (Default) - Best for Desktop/Server with AES-NI
   - **ChaCha20** - Best for Mobile/ARM/Embedded devices
   
3. **Click "ℹ️" button** for detailed cipher comparison

4. **Select File:** Click "Select File" and choose any file to encrypt

5. **Click "Run":** Watch the quantum key exchange simulation

6. **Save Encrypted File:** Choose location to save `.bb84` file

7. **Save Key B:** 
   - Click "Copy Key B" to copy to clipboard, OR
   - Click "Save Key B to .txt" to save to file
   - ⚠️ Keep this key secure - it's needed for decryption!

---

### 📥 **Decrypting a File:**

1. **Select Mode:** Choose "Decrypt" radio button

2. **Select Encrypted File:** Click "Select File" and choose a `.bb84` file

3. **Enter Key B:**
   - Paste the key directly, OR
   - Click "Import Key File" to load from `.txt` file

4. **Click "Run":** The cipher is auto-detected from the package

5. **Save Decrypted File:** Choose location to save original file

---

## 🔐 Cipher Selection Guide

### When to Use **AES-GCM**:
✅ Desktop/Server computers  
✅ Modern Intel/AMD CPUs with AES-NI  
✅ x86/x64 systems  
✅ 4-10x faster with hardware acceleration  

### When to Use **ChaCha20**:
✅ Mobile devices (phones, tablets)  
✅ ARM processors (Raspberry Pi, embedded)  
✅ Older CPUs without AES-NI  
✅ 5-15x faster on ARM/mobile  

**Both provide identical security:** 256-bit encryption, AEAD authentication, post-quantum signatures!

---

## 🎨 GUI Features

### New Features Added:

1. **Cipher Selection Dropdown**
   - Choose between AES-GCM and ChaCha20
   - Only visible in Encryption mode
   - Info button (ℹ️) shows detailed comparison

2. **Enhanced Output Messages**
   - Shows which cipher was used
   - Displays BB84 quantum key status
   - Shows post-quantum signature verification

3. **Auto-Detection in Decryption**
   - Automatically detects cipher from package
   - Works with both AES-GCM and ChaCha20 files
   - No need to specify cipher manually

4. **Visual Feedback**
   - Emoji indicators for status (✅ ❌ 🔐 📁)
   - Clear error messages with troubleshooting hints
   - Quantum process simulation animation

---

## 📊 Example Workflow

### Encrypt with ChaCha20:
```
1. Select "Encrypt" mode
2. Choose "ChaCha20 (Best for Mobile/ARM/Embedded)"
3. Click "Select File" → Choose "document.pdf"
4. Click "Run"
5. Watch quantum simulation
6. Save as "document.bb84"
7. Click "Save Key B to .txt" → Save as "Key_B.txt"
```

### Decrypt (Auto-Detects Cipher):
```
1. Select "Decrypt" mode
2. Click "Select File" → Choose "document.bb84"
3. Click "Import Key File" → Choose "Key_B.txt"
4. Click "Run"
5. System auto-detects ChaCha20 from package
6. Save decrypted file as "document.pdf"
```

---

## 📈 Metrics Report

After encryption/decryption, click **"Download Metrics Report (PDF)"** to get:
- Cipher algorithm used
- Encryption/decryption time
- Key confirmation status
- AEAD authentication result
- Post-quantum signature status
- File sizes (original vs encrypted)
- SHA-256 hashes

---

## 🔍 Troubleshooting

### "No file selected" error:
→ Click "Select File" button first

### "Invalid Key" error:
→ Key B must be binary string (only 0s and 1s)  
→ Check for spaces or invalid characters

### "Decryption failed" errors:
→ **Wrong Key B:** Doesn't match encryption key  
→ **Tampered file:** File was modified after encryption  
→ **Invalid format:** Not a valid `.bb84` file

### Import warnings (aes256_ctr_drbg):
→ These are harmless warnings from Dilithium library  
→ Encryption/decryption still works perfectly  
→ Post-quantum signatures still active

---

## 💡 Tips

1. **Always save Key B** - Without it, decryption is impossible!
2. **Use descriptive filenames** - Original filename is preserved in metadata
3. **Check metrics report** - Verify encryption success and key strength
4. **Test with small files first** - Verify the system works before encrypting important data
5. **Choose appropriate cipher** - Match cipher to your hardware for best performance

---

## 🎉 Success Indicators

### Encryption Success:
```
✅ File successfully encrypted with [Cipher]
📁 Saved to: [path]
🔐 Cipher: [AES-256-GCM or ChaCha20-Poly1305]
🔑 BB84 Quantum Key Distribution: Active
📜 Post-Quantum Signature: Dilithium5
```

### Decryption Success:
```
✅ File successfully decrypted!
📁 Saved to: [path]
📄 Original filename: [name]
🔐 Cipher: Auto-detected from package
✓ AEAD Authentication: Passed
✓ Post-Quantum Signature: Verified
```

---

## 🚀 Quick Start Commands

If GUI doesn't appear, run manually:
```bash
cd "c:\Users\Qadri laptop\Downloads\New folder (2)\BB84-Quantum-Encryption-Tool-Simulator"
python start_gui.py
```

---

## 📚 Additional Resources

- **Full Documentation:** See `CHACHA20_IMPLEMENTATION.md`
- **Quick Summary:** See `CHACHA20_SUMMARY.md`
- **Security Details:** See `SECURITY_IMPROVEMENTS.md`
- **Test Suite:** Run `python test_chacha20.py`

---

**Enjoy your quantum-safe encryption with cipher choice! 🔐**
