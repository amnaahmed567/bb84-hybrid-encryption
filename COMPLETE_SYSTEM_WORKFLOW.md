# Complete System Workflow - BB84 Quantum Encryption Tool
## Detailed Process Flow for Activity Diagram Creation

---

## 1. SYSTEM START

**Entry Point:** User launches application
```
Command: python start_gui.py
```

**Initial State:**
- GUI window opens (750x720 pixels)
- Title: "BB84 Quantum Encryption Tool (Simulator)"
- Mode: ENCRYPT (default selected)
- Cipher Selector: Visible (default: AES-GCM)
- Key B Input Field: Hidden
- Status: "Idle"

---

## 2. USER DECISION POINT 1: SELECT OPERATION MODE

**Decision:** User chooses between two modes

### **Branch A: ENCRYPT MODE** (Default)
**Action:** User clicks "Encrypt" radio button

**UI Changes:**
- Cipher selector dropdown: VISIBLE
- Key B input field: HIDDEN
- "Copy Key B" button: HIDDEN
- "Save Key B" button: HIDDEN

**Options Displayed:**
1. AES-GCM (Best for Desktop/Server with AES-NI) [DEFAULT]
2. ChaCha20 (Best for Mobile/ARM/Embedded)
3. AES-SIV (Misuse-resistant, No nonce required)

**Next Step:** Proceed to File Selection

### **Branch B: DECRYPT MODE**
**Action:** User clicks "Decrypt" radio button

**UI Changes:**
- Cipher selector dropdown: HIDDEN
- Key B input field: VISIBLE
- Entry placeholder: "Key B (only for decryption)"
- "Import Key File" button: VISIBLE

**Next Step:** Proceed to File Selection

---

## 3. FILE SELECTION PROCESS

**Action:** User clicks "Select File" button

**System Response:**
- Open native file browser dialog

### **For ENCRYPT Mode:**
**Valid Inputs:**
- Any file type: .pdf, .docx, .txt, .jpg, .png, .mp4, .csv, .zip, etc.
- Example: `document.pdf`, `image.jpg`, `video.mp4`

**System Processing:**
1. Store file path → `self.file_path`
2. Extract filename → `document.pdf`
3. Extract base name → `document` (without extension)
4. Store base name → `self.file_name_without_ext`
5. Update label → "Selected: document.pdf"

### **For DECRYPT Mode:**
**Valid Inputs:**
- Only `.bb84` encrypted files
- Example: `document_AES-GCM_E.bb84`, `image_CHACHA20_E.bb84`

**System Processing:**
1. Store file path → `self.file_path`
2. Parse filename to detect cipher type:
   - If contains "AES-GCM" → Set `self.cipher_used = "AES-GCM"`
   - If contains "CHACHA20" → Set `self.cipher_used = "CHACHA20"`
   - If contains "AES-SIV" → Set `self.cipher_used = "AES-SIV"`
3. Update label → "Selected: document_AES-GCM_E.bb84"

**Validation:**
- File path not empty → Continue
- File path empty → Show warning "No file selected"

---

## 4. ENCRYPTION MODE: CIPHER SELECTION

**Decision Point:** User selects encryption algorithm

### **Option 1: AES-GCM (Default)**
**Parameters:**
- Algorithm: AES-256-GCM (Galois/Counter Mode)
- Block size: 128 bits
- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)
- Tag size: 128 bits (16 bytes)
- Mode: AEAD (Authenticated Encryption with Associated Data)

**Best For:**
- Desktop/Server systems
- Intel/AMD processors with AES-NI hardware acceleration
- High-throughput scenarios (4-10 GB/s)

**Stored Value:** `cipher = "AES-GCM"`

### **Option 2: ChaCha20-Poly1305**
**Parameters:**
- Algorithm: ChaCha20 stream cipher + Poly1305 MAC
- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)
- Tag size: 128 bits (16 bytes)
- Rounds: 20 rounds of ARX operations
- Mode: AEAD

**Best For:**
- ARM/Mobile/Embedded devices
- Systems without AES-NI hardware
- Constant-time security requirements (500-800 MB/s)

**Stored Value:** `cipher = "ChaCha20"`

### **Option 3: AES-SIV**
**Parameters:**
- Algorithm: AES-256-SIV (Synthetic IV Mode)
- Key size: 512 bits (64 bytes = 2×256-bit keys)
- Nonce size: NONE (deterministic encryption)
- Tag size: 128 bits (16 bytes, SIV serves as tag)
- Mode: Misuse-resistant AEAD

**Best For:**
- Research/High-security applications
- Scenarios where nonce management is difficult
- Deterministic encryption requirements

**Stored Value:** `cipher = "AES-SIV"`

**Next Step:** User clicks "Run" button

---

## 5. DECRYPTION MODE: KEY INPUT

**Decision Point:** User provides Key B

### **Method A: Manual Paste**
**Process:**
1. User copies Key B from secure storage
2. User pastes into entry field
3. Example: `1101010010110101100110...` (256 bits)

**Validation:**
- Check format: Must contain only '0' and '1' characters
- Check length: Must be exactly 256 bits
- If invalid → Show error "Key B must be a binary string (only 0s and 1s)"

### **Method B: Import from File**
**Process:**
1. User clicks "Import Key File" button
2. File browser opens (filter: .txt files)
3. User selects key file (e.g., `document_AES-GCM_key.txt`)
4. System reads file content
5. System validates content (0s and 1s only, 256 bits)
6. System populates entry field with Key B

**Next Step:** User clicks "Run" button

---

## 6. RUN BUTTON PRESSED - SYSTEM DISPATCH

**Action:** User clicks "Run" button

**Validation Check:**
```
IF file_path is empty:
    Show warning "Please select a file first"
    STOP
ELSE:
    Continue to process
```

**System Action:**
- Clear output log display
- Create new thread for processing (prevents GUI freeze)
- Dispatch based on mode:
  - If mode = "ENCRYPT" → Go to ENCRYPTION WORKFLOW
  - If mode = "DECRYPT" → Go to DECRYPTION WORKFLOW

---

## 7. ENCRYPTION WORKFLOW

### **PHASE 1: BB84 QUANTUM KEY DISTRIBUTION**

#### **Step 1.1: Initialize Quantum Channel**
**Visual Status:** "Initializing quantum channel..."

**System Action:**
- Call `run_qkd_demo()` function
- Set parameters:
  ```python
  length = 1024  # Number of qubits
  biased = True
  p_Z = 0.8  # 80% Z-basis, 20% X-basis
  p_depolarize = 0.012  # 1.2% depolarizing noise
  p_loss = 0.03  # 3% photon loss
  dark_count = 0.01  # 1% detector dark counts
  attack = "intercept_resend"
  attack_fraction = 0.08  # Eve attacks 8% of qubits
  shots_per_qubit = 6  # Measurement shots per qubit
  authenticate = True
  eps_sec = 1e-10  # Security parameter
  ```

#### **Step 1.2: Alice Generates Qubits**
**Visual Status:** "Alice generates random bits + biased bases..."

**Process:**
1. **Generate random bits:**
   - Create array of 1024 random bits
   - Example: `[0, 1, 1, 0, 1, 0, 1, 1, ...]`
   - Source: `secrets.SystemRandom()` (cryptographically secure)

2. **Choose preparation bases:**
   - For each bit, choose basis:
     - 80% chance: Z-basis (computational basis: |0⟩, |1⟩)
     - 20% chance: X-basis (Hadamard basis: |+⟩, |−⟩)
   - Example: `['Z', 'Z', 'X', 'Z', 'Z', 'X', ...]`

3. **Prepare qubits:**
   - If bit=0 and basis=Z → Prepare |0⟩ state
   - If bit=1 and basis=Z → Prepare |1⟩ state
   - If bit=0 and basis=X → Prepare |+⟩ state (H|0⟩)
   - If bit=1 and basis=X → Prepare |−⟩ state (H|1⟩)

**Output:** 1024 prepared qubits ready for transmission

#### **Step 1.3: Channel Transmission with Noise**
**Visual Status:** "Channel noise/loss modeling active..."

**Process:**
For each qubit passing through quantum channel:

1. **Depolarizing Noise (p=0.012):**
   - Random number r ∈ [0,1]
   - If r < 0.012: Apply random Pauli gate (X, Y, or Z)
   - Effect: Bit flip or phase flip (simulates decoherence)

2. **Photon Loss (p=0.03):**
   - Random number r ∈ [0,1]
   - If r < 0.03: Mark qubit as "lost"
   - Effect: Bob won't receive this qubit (detection failure)

3. **Dark Counts (p=0.01):**
   - Random number r ∈ [0,1]
   - If r < 0.01: Random detector click (false positive)
   - Effect: Bob measures random bit regardless of actual state

**Output:** Noisy qubits ready for Bob's measurement

#### **Step 1.4: Optional Eavesdropper Attack**
**Visual Status:** "(Optional) Eavesdropper intercept-resend simulation..."

**Process (if attack_fraction > 0):**
For each qubit:
1. **Intercept decision:**
   - Random number r ∈ [0,1]
   - If r < 0.08: Eve intercepts this qubit
   - Otherwise: Qubit passes untouched

2. **Eve's measurement:**
   - Eve chooses random basis (50% Z, 50% X)
   - Eve measures qubit (collapses state)
   - Eve records measurement result

3. **Eve's resend:**
   - Eve prepares new qubit in measured state
   - Eve sends to Bob
   - Problem: If Eve chose wrong basis, she introduces errors

**Effect:** Increases QBER (Quantum Bit Error Rate)

#### **Step 1.5: Bob Measures Qubits**
**Visual Status:** "Bob measures qubits with chosen bases..."

**Process:**
For each received qubit:
1. **Bob chooses measurement basis:**
   - Independent choice (80% Z, 20% X)
   - Example: `['Z', 'X', 'Z', 'Z', 'X', ...]`

2. **Bob performs measurement (6 shots):**
   - Measure qubit 6 times (allows stochastic outcomes)
   - Record results: e.g., `[0, 0, 1, 0, 0, 0]`
   - Take majority vote: Result = 0 (appears 5/6 times)

3. **Store measurement result:**
   - Bob's bit array: `[0, 1, 0, 1, 1, ...]`

**Output:** Bob's raw measurement results (1024 bits)

#### **Step 1.6: Basis Reconciliation**
**Visual Status:** "Basis reconciliation & sampling..."

**Process:**
1. **Public channel communication:**
   - Alice broadcasts: "My bases were: ZXXZZ..."
   - Bob broadcasts: "My bases were: XZXZZ..."
   - Communication is public (eavesdropper can listen)

2. **Basis comparison:**
   - Compare Alice's and Bob's bases position-by-position
   - Keep bits only where bases matched
   - Example:
     ```
     Position:  0   1   2   3   4   5
     Alice:     Z   Z   X   Z   Z   X
     Bob:       X   Z   X   Z   X   X
     Match:     ✗   ✓   ✓   ✓   ✗   ✓
     Keep:          1       2   3       4
     ```

3. **Sifting:**
   - Discard bits where bases didn't match
   - Remove "lost" qubits (photon loss)
   - Typical efficiency: ~65% (with 80/20 bias)
   - **Sifted key length:** ~667 bits (from 1024 original)

**Output:** 
- Alice's sifted key: `[0, 1, 1, 0, ...]` (667 bits)
- Bob's sifted key: `[0, 1, 1, 0, ...]` (667 bits, mostly matching)

#### **Step 1.7: Key Confirmation (Eavesdropping Detection)**
**Visual Status:** "Key confirmation & QBER calculation..."

**Process:**
1. **Sacrifice sample bits:**
   - Randomly select 20 bit positions
   - Example: positions [5, 12, 23, 41, ...]

2. **Public comparison:**
   - Alice: "My bit at position 5 is 0"
   - Bob: "My bit at position 5 is 0" ✓ Match
   - Alice: "My bit at position 12 is 1"
   - Bob: "My bit at position 12 is 0" ✗ Mismatch
   - Continue for all 20 positions

3. **Calculate QBER (Quantum Bit Error Rate):**
   ```
   Mismatches = 1 (example)
   QBER = Mismatches / Sample_size
   QBER = 1 / 20 = 0.05 = 5%
   ```

4. **Threshold check:**
   ```
   IF QBER > 0.15 (15%):
       Abort encryption
       Display: "High error rate detected. Possible eavesdropping."
       STOP
   ELSE:
       Continue with remaining bits
   ```

5. **Remove sacrificed bits:**
   - Remaining sifted key: 667 - 20 = 647 bits

**Output:** 
- **QBER:** Typically 1-5% (realistic with noise/attack)
- **Remaining key:** 647 bits
- **Status:** PASSED (if QBER ≤ 15%)

#### **Step 1.8: Privacy Amplification**
**Visual Status:** "Privacy & finite-key analysis computed..."

**Process:**
1. **Calculate secure key length (ell):**
   ```python
   n_sifted = 647
   QBER = 0.024 (example: 2.4%)
   
   # Binary entropy function
   h(QBER) = -QBER * log2(QBER) - (1-QBER) * log2(1-QBER)
   h(0.024) ≈ 0.165
   
   # Leaked information during error correction
   leakEC = 1.2 * n_sifted * h(QBER) ≈ 128 bits
   
   # Security parameter
   log2(1/eps_sec) = log2(1/1e-10) ≈ 33 bits
   
   # Final secure length
   ell = n_sifted * (1 - h(QBER)) - leakEC - 33
   ell = 647 * (1 - 0.165) - 128 - 33
   ell ≈ 379 bits
   ```

2. **Truncate to required length:**
   - Need: 256 bits for encryption key
   - Have: 647 bits available, 379 bits provably secure
   - Action: Take first 256 bits from sifted key
   - Discard remaining bits

**Output:**
- **Key A (Alice):** 256 bits `[1,1,0,1,0,1,0,0,1,0,...]`
- **Key B (Bob):** 256 bits `[1,1,0,1,0,1,0,0,1,0,...]`
- **ell (secure length):** ~379 bits (theoretical maximum)
- **QKD Statistics:** Stored for metrics

---

### **PHASE 2: KEY DERIVATION (HKDF)**

**Visual Status:** "Key used to derive [cipher] key..."

#### **Step 2.1: Generate Salt**
**Process:**
- Generate random 16-byte (128-bit) salt
- Source: `os.urandom(16)` (cryptographically secure)
- Example: `b'\x8f\x2a\x91\xc4\x7e\x3b...'`

**Purpose:** Ensures unique key derivation even with same input key

#### **Step 2.2: HKDF-Extract Phase**
**Process:**
```
Input: 
  - IKM (Input Key Material): Key A (256 bits from BB84)
  - Salt: 16 bytes

Algorithm: HMAC-SHA256
  PRK = HMAC-SHA256(salt, IKM)

Output:
  - PRK (Pseudorandom Key): 32 bytes (256 bits)
```

**Purpose:** Extract high-entropy key from BB84 bits

#### **Step 2.3: HKDF-Expand Phase**
**Process:**
Generate multiple keys from single PRK using different "info" labels:

**For AES-GCM / ChaCha20 (256-bit keys):**
```
Encryption Key:
  Input: PRK, info="encryption_key", length=32
  Output: 32-byte encryption key
  
Authentication Key:
  Input: PRK, info="auth_key", length=32
  Output: 32-byte HMAC key (optional)
  
Signature Key:
  Derived separately for Dilithium5 keypair
```

**For AES-SIV (512-bit key):**
```
Encryption Key:
  Input: PRK, info="encryption_key", length=64
  Output: 64-byte key (two 256-bit keys concatenated)
```

**Output:**
- **Encryption Key:** Ready for AEAD cipher
- **Key Separation:** Each key serves single purpose (prevents reuse attacks)

---

### **PHASE 3: FILE ENCRYPTION (CIPHER-SPECIFIC)**

**Visual Status:** "Encryption process complete."

#### **BRANCH 3A: AES-GCM ENCRYPTION**
**Selected when:** User chose "AES-GCM" from dropdown

##### **Step 3A.1: Read File**
```
Input: File path (e.g., "document.pdf")
Process: Read binary content
Output: file_bytes (raw data)
Example: b'\x25\x50\x44\x46...' (PDF header)
```

##### **Step 3A.2: Generate Nonce**
```
Process: Generate 12-byte random nonce
Source: os.urandom(12)
Output: nonce = b'\x3a\x9f\x12...'
Purpose: Ensures unique encryption (NEVER reuse!)
```

##### **Step 3A.3: Prepare AAD (Additional Authenticated Data)**
```
Components:
  - Version string: "AES-GCM-v1"
  - Original filename: "document.pdf"
  - Salt: 16 bytes

Process:
  aad = version.encode() + filename.encode() + salt

Output: aad byte string
Purpose: Authenticated but NOT encrypted (tamper detection)
```

##### **Step 3A.4: AES-GCM Encryption**
```
Algorithm: AES-256-GCM
Input:
  - key: 32 bytes (from HKDF)
  - nonce: 12 bytes (random)
  - plaintext: file_bytes
  - associated_data: aad

Process:
  1. Initialize AES-GCM cipher with key
  2. Set nonce (IV)
  3. Add AAD (authenticated, not encrypted)
  4. Encrypt plaintext in GCM mode
  5. Generate authentication tag

Output:
  - ciphertext: Encrypted file bytes
  - tag: 16-byte authentication tag

Formula: ciphertext || tag = AESGCM(key).encrypt(nonce, plaintext, aad)
```

##### **Step 3A.5: Generate Dilithium5 Signature**
```
Algorithm: CRYSTALS-Dilithium (NIST PQC Level 5)

Step 1: Generate keypair
  - Private key (sk): ~4864 bytes
  - Public key (pk): ~2592 bytes

Step 2: Create signed data
  signed_data = aad + ciphertext

Step 3: Sign with private key
  signature = dilithium5.sign(sk, signed_data)
  Output: ~4595 bytes

Purpose: Post-quantum authentication (quantum-resistant)
```

##### **Step 3A.6: Package Assembly**
```
Create JSON structure:
{
  "ciphertext": base64_encode(ciphertext),
  "salt": base64_encode(salt),
  "nonce": base64_encode(nonce),
  "version": "AES-GCM-v1",
  "filename": "document.pdf",
  "pq_signature": base64_encode(signature),
  "pq_public_key": base64_encode(pk)
}

Process:
  1. Serialize JSON
  2. Convert to bytes
  3. Base64 encode entire package

Output: Base64 string (encrypted package)
```

##### **Step 3A.7: Save Encrypted File**
```
Auto-generated filename: document_AES-GCM_E.bb84

Process:
  1. Open file dialog
  2. Suggest default name
  3. User confirms save location
  4. Write Base64 string to file
  5. Close file

Output: .bb84 file on disk
```

---

#### **BRANCH 3B: ChaCha20-Poly1305 ENCRYPTION**
**Selected when:** User chose "ChaCha20" from dropdown

##### **Step 3B.1-3B.3: Same as AES-GCM**
- Read file
- Generate 12-byte nonce
- Prepare AAD (version="ChaCha20-v1")

##### **Step 3B.4: ChaCha20-Poly1305 Encryption**
```
Algorithm: ChaCha20 (stream cipher) + Poly1305 (MAC)

Step 1: Initialize ChaCha20 state
  - key: 32 bytes (from HKDF)
  - nonce: 12 bytes
  - counter: 32-bit (starts at 0)

Step 2: Generate keystream
  Process:
    - ChaCha20 quarter-round operations (20 rounds)
    - Operations: Add, Rotate, XOR (ARX)
    - Produces pseudorandom keystream
  
  State matrix (4×4):
    constant constant constant constant
    key      key      key      key
    key      key      key      key
    counter  counter  nonce    nonce

Step 3: Encrypt plaintext
  ciphertext = plaintext XOR keystream
  (Stream cipher operation)

Step 4: Generate Poly1305 MAC
  Input: ciphertext + aad
  Key: First 32 bytes of ChaCha20 keystream
  Output: 16-byte authentication tag

Output:
  - ciphertext: Encrypted data
  - tag: 16-byte Poly1305 tag
```

##### **Step 3B.5-3B.7: Same as AES-GCM**
- Dilithium5 signature
- Package assembly (version="ChaCha20-v1")
- Save as: `document_CHACHA20_E.bb84`

---

#### **BRANCH 3C: AES-SIV ENCRYPTION**
**Selected when:** User chose "AES-SIV" from dropdown

##### **Step 3C.1: Read File**
Same as AES-GCM

##### **Step 3C.2: NO NONCE GENERATION**
```
Key difference: AES-SIV is deterministic
  - No random nonce needed
  - Same plaintext → same ciphertext
  - Misuse-resistant (safe against nonce reuse)
```

##### **Step 3C.3: Prepare AAD**
```
Components:
  - Version: "AES-SIV-v1"
  - Filename: "document.pdf"
  - Salt: 16 bytes

aad = [version.encode() + filename.encode() + salt]
Note: AAD is a list for AES-SIV API
```

##### **Step 3C.4: AES-SIV Encryption**
```
Algorithm: AES-256-SIV (Synthetic IV mode)

Input:
  - key: 64 bytes (two 256-bit keys from HKDF)
    - K1: 32 bytes (for CMAC/SIV generation)
    - K2: 32 bytes (for CTR encryption)
  - plaintext: file_bytes
  - associated_data: [aad] (list)

Step 1: Generate SIV (Synthetic IV)
  Process:
    - Compute CMAC over plaintext + AAD using K1
    - Result: 16-byte SIV (serves as IV and tag)
  
  SIV = CMAC(K1, plaintext || aad)

Step 2: Encrypt with CTR mode
  Process:
    - Use SIV as IV for AES-CTR
    - Encrypt plaintext with K2
    - Result: ciphertext
  
  ciphertext = AES-CTR(K2, SIV, plaintext)

Output: SIV || ciphertext
  - SIV: 16 bytes (authentication tag)
  - ciphertext: Encrypted data
```

##### **Step 3C.5-3C.7: Similar to AES-GCM**
- Dilithium5 signature
- Package assembly (version="AES-SIV-v1", nonce=null)
- Save as: `document_AES-SIV_E.bb84`

---

### **PHASE 4: POST-ENCRYPTION DISPLAY**

#### **Step 4.1: Display QKD Statistics**
```
Output to GUI:
QKD Stats → Sifted: 667, QBER: 0.0234, ell: 379.56
```

#### **Step 4.2: Display Encryption Success**
```
Output:
✅ File successfully encrypted with [Cipher Name]
📁 Saved to: C:\path\to\document_[CIPHER]_E.bb84
🔐 Cipher: AES-256-GCM / ChaCha20-Poly1305 / AES-SIV
🔑 BB84 Quantum Key Distribution: Active
📜 Post-Quantum Signature: Dilithium5

Key B (required for decryption):
110101001011010110...01010 (256 bits)

⚠️  IMPORTANT: Save Key B securely! It's needed for decryption.

Key B Strength Estimate: Strong (1s: 128, 0s: 128)
```

#### **Step 4.3: Show Key B Management Buttons**
```
Buttons appear:
  1. "Copy Key B" → Copies binary string to clipboard
  2. "Save Key B to .txt" → Saves as document_[CIPHER]_key.txt
```

#### **Step 4.4: Export Metrics**
```
Auto-generated file: bb84_metrics.json

Contents:
{
  "Timestamp": "2025-12-12 10:30:45.123456",
  "Original File Size (bytes)": 152048,
  "Encrypted File Size (bytes)": 158720,
  "Key A Length": 256,
  "Key B Length": 256,
  "Key B - Count of 1s": 128,
  "Key B - Count of 0s": 128,
  "A/B Bit Match Percentage": 97.66,
  "Estimated Shannon Entropy": 0.9998,
  "SHA-256 Hash of Encrypted File": "a3f2c8...",
  "AEAD Authentication": "Passed",
  "Key Confirmation": "Passed",
  "Key Confirmation Error Rate": 0.0234,
  "Post-Quantum Signature": "Enabled",
  "Cipher Algorithm": "AES-GCM",
  "QKD - Sifted Length": 667,
  "QKD - QBER": 0.0234,
  "QKD - Final Secure Length (ell)": 379.56,
  "Encryption Time (s)": 0.8542
}
```

**End of Encryption Workflow**

---

## 8. DECRYPTION WORKFLOW

### **PHASE 1: FILE LOADING**

#### **Step 1.1: Read Encrypted File**
```
Input: .bb84 file (e.g., document_AES-GCM_E.bb84)

Process:
  1. Open file in text mode
  2. Read entire content (Base64 string)
  3. Store as: encrypted_base64

Example content:
"eyJjaXBoZXJ0ZXh0IjogIi4uLiIsICJzYWx0IjogIi4uLiIsIC4uLn0="
```

#### **Step 1.2: Base64 Decode**
```
Process:
  package_bytes = base64.b64decode(encrypted_base64)

Output: Raw bytes (JSON structure)
```

#### **Step 1.3: Parse JSON Package**
```
Process:
  package_dict = json.loads(package_bytes)

Extract components:
  - ciphertext: base64.b64decode(package_dict["ciphertext"])
  - salt: base64.b64decode(package_dict["salt"])
  - nonce: base64.b64decode(package_dict["nonce"]) or None
  - version: package_dict["version"]
  - filename: package_dict["filename"]
  - pq_signature: base64.b64decode(package_dict["pq_signature"])
  - pq_public_key: base64.b64decode(package_dict["pq_public_key"])
```

---

### **PHASE 2: CIPHER AUTO-DETECTION**

#### **Step 2.1: Parse Version Field**
```
Decision logic:
  IF version == "AES-GCM-v1":
      cipher_mode = "AES-GCM"
      has_nonce = True
      
  ELSE IF version == "ChaCha20-v1":
      cipher_mode = "ChaCha20"
      has_nonce = True
      
  ELSE IF version == "AES-SIV-v1":
      cipher_mode = "AES-SIV"
      has_nonce = False
      
  ELSE:
      ERROR: Unknown cipher version
      STOP
```

**Output:** Detected cipher mode

---

### **PHASE 3: SIGNATURE VERIFICATION (Verify-Before-Decrypt)**

#### **Step 3.1: Reconstruct Signed Data**
```
Process:
  aad = version.encode() + filename.encode() + salt
  signed_data = aad + ciphertext

Purpose: Must match exactly what was signed during encryption
```

#### **Step 3.2: Verify Dilithium5 Signature**
```
Algorithm: CRYSTALS-Dilithium verification

Input:
  - public_key: pq_public_key (2592 bytes)
  - signature: pq_signature (4595 bytes)
  - message: signed_data

Process:
  valid = dilithium5.verify(public_key, signature, signed_data)

Decision:
  IF valid == True:
      Continue to decryption
  ELSE:
      ERROR: "Invalid signature - file tampered"
      Display error message
      STOP (abort immediately)

Optimization: Verify-before-decrypt
  - Saves CPU cycles (no expensive decryption)
  - 5-6× faster rejection of tampered files
  - DoS attack prevention
```

---

### **PHASE 4: KEY DERIVATION (Bob's Side)**

#### **Step 4.1: Validate Key B Input**
```
Input: Key B from entry field (256-bit binary string)

Validation:
  1. Check format: Only '0' and '1' characters
  2. Check length: Exactly 256 bits
  
  IF invalid:
      ERROR: "Key B must be a binary string (only 0s and 1s)"
      STOP
```

#### **Step 4.2: Convert to Bit Array**
```
Process:
  key_b_str = "110101001011..."
  key_b_bits = [int(b) for b in key_b_str]

Output: [1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, ...]
```

#### **Step 4.3: HKDF Key Derivation**
```
Input:
  - IKM: key_b_bits (256 bits from BB84)
  - Salt: Extracted from package (16 bytes)

HKDF-Extract:
  PRK = HMAC-SHA256(salt, IKM)

HKDF-Expand:
  IF cipher_mode == "AES-SIV":
      decryption_key = HKDF-Expand(PRK, "encryption_key", 64)
  ELSE:
      decryption_key = HKDF-Expand(PRK, "encryption_key", 32)

Output: Decryption key (32 or 64 bytes)
```

---

### **PHASE 5: AEAD DECRYPTION (Cipher-Specific)**

#### **BRANCH 5A: AES-GCM DECRYPTION**

##### **Step 5A.1: Rebuild AAD**
```
Process:
  aad = version.encode() + filename.encode() + salt

Note: Must match encryption AAD exactly (byte-for-byte)
```

##### **Step 5A.2: AES-GCM Decryption**
```
Algorithm: AES-256-GCM

Input:
  - key: 32 bytes (from HKDF)
  - nonce: 12 bytes (from package)
  - ciphertext: Encrypted data
  - aad: Reconstructed AAD
  - tag: 16 bytes (embedded in ciphertext)

Process:
  try:
      plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
  except InvalidTag:
      ERROR: "AEAD authentication failed"
      STOP

Internal verification:
  1. Recalculate authentication tag
  2. Compare with tag in ciphertext
  3. If mismatch → Raise InvalidTag exception
  4. If match → Decrypt and return plaintext

Output: Decrypted plaintext (original file bytes)
```

---

#### **BRANCH 5B: ChaCha20-Poly1305 DECRYPTION**

##### **Step 5B.1: Rebuild AAD**
Same as AES-GCM

##### **Step 5B.2: ChaCha20-Poly1305 Decryption**
```
Algorithm: ChaCha20 + Poly1305

Input:
  - key: 32 bytes
  - nonce: 12 bytes
  - ciphertext: Encrypted data
  - aad: Reconstructed AAD
  - tag: 16 bytes

Step 1: Verify Poly1305 MAC
  - Recompute MAC over ciphertext + aad
  - Compare with received tag
  - If mismatch → ERROR

Step 2: Generate ChaCha20 keystream
  - Initialize state with key + nonce
  - Run 20 rounds of ARX operations
  - Generate same keystream as encryption

Step 3: Decrypt
  plaintext = ciphertext XOR keystream

Output: Decrypted plaintext
```

---

#### **BRANCH 5C: AES-SIV DECRYPTION**

##### **Step 5C.1: Rebuild AAD**
```
aad = [version.encode() + filename.encode() + salt]
Note: List format for AES-SIV API
```

##### **Step 5C.2: AES-SIV Decryption**
```
Algorithm: AES-256-SIV

Input:
  - key: 64 bytes (K1 + K2)
  - ciphertext: SIV || encrypted_data
  - aad: [aad]

Step 1: Extract SIV
  SIV = ciphertext[0:16]  # First 16 bytes
  encrypted_data = ciphertext[16:]  # Remaining bytes

Step 2: Decrypt with CTR mode
  plaintext = AES-CTR(K2, SIV, encrypted_data)

Step 3: Verify SIV
  expected_SIV = CMAC(K1, plaintext || aad)
  
  IF expected_SIV != SIV:
      ERROR: "SIV authentication failed"
      STOP

Output: Verified and decrypted plaintext
```

---

### **PHASE 6: FILE EXTRACTION**

#### **Step 6.1: Parse Internal Payload**
```
Process:
  1. Interpret plaintext as JSON
  2. Extract: file_bytes, original_filename, extension

Example:
{
  "file_bytes": "base64_encoded_data",
  "metadata": {
    "original_filename": "document.pdf",
    "extension": "pdf"
  }
}
```

#### **Step 6.2: Base64 Decode File Bytes**
```
decrypted_data = base64.b64decode(file_bytes)
```

#### **Step 6.3: Generate Output Filename**
```
Auto-naming logic:
  encrypted_filename = "document_AES-GCM_E.bb84"
  base_name = "document_AES-GCM_E"
  extension = "pdf"
  
  output_filename = base_name + "_decrypted." + extension
  Result: "document_AES-GCM_E_decrypted.pdf"
```

#### **Step 6.4: Save Decrypted File**
```
Process:
  1. Open file dialog
  2. Suggest default name: document_AES-GCM_E_decrypted.pdf
  3. User confirms save location
  4. Write decrypted_data to file
  5. Close file

Output: Restored original file on disk
```

---

### **PHASE 7: POST-DECRYPTION DISPLAY**

#### **Step 7.1: Display Success Message**
```
Output:
✅ File successfully decrypted!
📁 Saved to: C:\path\to\document_AES-GCM_E_decrypted.pdf
📄 Original filename: document.pdf
🔐 Cipher: Auto-detected from package
✓ AEAD Authentication: Passed
✓ Post-Quantum Signature: Verified
```

#### **Step 7.2: Update Metrics**
```
Add to bb84_metrics.json:
{
  ...existing encryption metrics...
  "Decrypted File Size (bytes)": 152048,
  "SHA-256 Hash of Decrypted File": "b4e9a2...",
  "Decryption Time (s)": 0.3214
}
```

**End of Decryption Workflow**

---

## 9. ERROR HANDLING FLOWS

### **ERROR A: Wrong Key B**
```
Trigger: Key B doesn't match encryption Key A

Detection point: AEAD tag verification fails

Process:
  1. AESGCM.decrypt() raises InvalidTag exception
  2. Catch exception
  3. Display error message:
  
❌ Decryption failed: Invalid Key B or tampered file

Possible reasons:
• Wrong Key B (doesn't match encryption key)
• Tampered or corrupted file
• Invalid package format

Action: STOP decryption, return to main screen
```

---

### **ERROR B: Tampered Ciphertext**
```
Trigger: Ciphertext modified after encryption

Detection points:
  1. Dilithium signature verification (first check)
  2. AEAD tag verification (second check)

Process:
  1. Signature verification fails → Immediate rejection
  2. Display: "Invalid signature - file tampered"
  3. STOP (no decryption attempted)

Advantage: Verify-before-decrypt saves CPU
```

---

### **ERROR C: High QBER (Eavesdropping)**
```
Trigger: QBER > 15% during key confirmation

Process:
  1. Sample 20 bits
  2. Calculate error rate: 4/20 = 20% (example)
  3. Check: 20% > 15% threshold
  4. Abort encryption
  5. Display:

❌ High error rate detected (20.00%)
Possible eavesdropping. Encryption aborted.

Action: STOP encryption, return to file selection
```

---

### **ERROR D: Invalid File Format**
```
Trigger: Selected file not .bb84 in decrypt mode

Process:
  1. Attempt to parse JSON
  2. JSON parsing fails
  3. Display: "Invalid package format"
  4. STOP

Or: Version field unrecognized
  Display: "Unknown cipher version"
```

---

## 10. METRICS REPORT GENERATION

### **Step 10.1: User Clicks "Download Metrics Report (PDF)"**

### **Step 10.2: Load Metrics Data**
```
Process:
  1. Read bb84_metrics.json
  2. Parse JSON to dictionary
  
  IF file not found:
      ERROR: "Metrics file not found"
      STOP
```

### **Step 10.3: Generate PDF**
```
Library: fpdf2

Process:
  1. Create PDF object
  2. Add page
  3. Set header: "BB84 Metrics Report"
  4. For each metric:
      - Add line: "Key: Value"
  5. Save to buffer
```

### **Step 10.4: Auto-Generate Filename**
```
Logic:
  IF operation_type == "encrypt":
      filename = "[original_name]_[cipher]_report_encryption.pdf"
      Example: "document_AES-GCM_report_encryption.pdf"
  
  ELSE IF operation_type == "decrypt":
      filename = "[encrypted_name]_report_decryption.pdf"
      Example: "document_AES-GCM_E_report_decryption.pdf"
```

### **Step 10.5: Save PDF**
```
Process:
  1. Open file dialog
  2. Suggest default name
  3. User confirms save location
  4. Write PDF to file
  5. Display: "PDF report saved to: [path]"
```

---

## 11. ACTIVITY DIAGRAM FLOW SUMMARY

### **Main Flow Nodes:**
1. **START** → GUI Initialization
2. **DECISION** → Select Mode (Encrypt/Decrypt)
3. **ACTION** → Select File
4. **DECISION** → If Encrypt: Choose Cipher
5. **ACTION** → Click Run
6. **SUBPROCESS** → BB84 QKD Protocol
   - Alice generates bits
   - Channel transmission (noise)
   - Eve attack (optional)
   - Bob measures
   - Basis reconciliation
   - Key confirmation
   - Privacy amplification
7. **SUBPROCESS** → HKDF Key Derivation
8. **DECISION** → Cipher Branch (AES-GCM / ChaCha20 / AES-SIV)
9. **ACTION** → Encrypt File
10. **ACTION** → Generate Signature
11. **ACTION** → Package Assembly
12. **ACTION** → Save .bb84 File
13. **ACTION** → Display Key B
14. **END** → Encryption Complete

### **Decryption Flow Nodes:**
1. **START** → From main menu (Decrypt mode)
2. **ACTION** → Select .bb84 File
3. **ACTION** → Enter Key B
4. **ACTION** → Click Run
5. **ACTION** → Load Package
6. **ACTION** → Parse JSON
7. **DECISION** → Auto-detect Cipher
8. **ACTION** → Verify Signature (First!)
9. **DECISION** → Signature Valid?
   - NO → Display Error → END
   - YES → Continue
10. **ACTION** → Derive Key from Key B
11. **ACTION** → Rebuild AAD
12. **DECISION** → Cipher Branch (AES-GCM / ChaCha20 / AES-SIV)
13. **ACTION** → Decrypt & Verify AEAD
14. **DECISION** → AEAD Valid?
   - NO → Display Error → END
   - YES → Continue
15. **ACTION** → Extract Payload
16. **ACTION** → Save Decrypted File
17. **ACTION** → Display Success
18. **END** → Decryption Complete

---

## 12. KEY DECISION POINTS FOR DIAGRAM

### **Diamond Nodes (Decisions):**
1. Mode Selection: Encrypt or Decrypt?
2. Cipher Selection: AES-GCM, ChaCha20, or AES-SIV?
3. QBER Check: QBER ≤ 15%?
4. Signature Valid: Yes or No?
5. AEAD Tag Valid: Yes or No?
6. Key B Format Valid: Binary string?

### **Process Nodes (Rectangles):**
- File Selection
- BB84 Protocol Execution
- Key Derivation (HKDF)
- Encryption/Decryption
- Signature Generation/Verification
- File Save

### **Subprocess Nodes (Rounded Rectangles):**
- BB84 QKD (contains multiple sub-steps)
- HKDF (contains Extract + Expand)
- AES-GCM/ChaCha20/AES-SIV Encryption
- AEAD Decryption

### **Parallel Flows (Fork/Join):**
- Visual status updates (runs parallel to main process)
- Metrics collection (background thread)

---

## 13. TIMING AND PERFORMANCE

### **Typical Execution Times:**
```
BB84 QKD Protocol: 1-2 seconds
  - Alice bit generation: 0.1s
  - Channel simulation: 0.5s
  - Bob measurement: 0.3s
  - Basis reconciliation: 0.2s
  - Key confirmation: 0.1s

HKDF Key Derivation: 0.01s

Encryption (1 MB file):
  - AES-GCM: 0.05-0.1s (with AES-NI)
  - ChaCha20: 0.1-0.2s
  - AES-SIV: 0.15-0.3s

Dilithium5 Signature:
  - Generation: 0.05s
  - Verification: 0.02s

Total Encryption Time: 1.5-3 seconds
Total Decryption Time: 0.5-1 second
```

---

## 14. FILE FORMAT SPECIFICATION

### **.bb84 File Structure:**
```
Outer layer: Base64-encoded JSON

Inner structure (after Base64 decode):
{
  "ciphertext": "base64_string",      // Encrypted file data
  "salt": "base64_string",             // 16-byte HKDF salt
  "nonce": "base64_string" | null,     // 12-byte nonce (null for AES-SIV)
  "version": "string",                 // Cipher identifier
  "filename": "string",                // Original filename
  "pq_signature": "base64_string",     // Dilithium5 signature (4595 bytes)
  "pq_public_key": "base64_string"     // Dilithium5 public key (2592 bytes)
}

Version values:
  - "AES-GCM-v1"
  - "ChaCha20-v1"
  - "AES-SIV-v1"

Total file size: Original size + ~15-20 KB overhead
  (Signature + public key + metadata)
```

---

This complete workflow document contains every detail needed to create a comprehensive activity diagram, including all decision points, processes, error handling, and technical specifications!
