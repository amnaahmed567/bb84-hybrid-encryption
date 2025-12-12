# BB84 Quantum Encryption Tool - Activity Diagram

## Complete System Activity Diagram

This diagram shows the complete workflow of the BB84 Quantum Encryption Tool with all decision points, processes, and cipher branches.

---

## Main Activity Diagram (Mermaid Syntax)

```mermaid
flowchart TD
    Start([User Launches Application]) --> Init[Initialize GUI<br/>Mode: ENCRYPT<br/>Cipher: AES-GCM<br/>Status: Idle]
    Init --> ModeSelect{Select Operation<br/>Mode?}
    
    %% ENCRYPTION BRANCH
    ModeSelect -->|Encrypt| ShowCipher[Show Cipher Selector<br/>Hide Key B Input]
    ShowCipher --> SelectFile1[User Clicks<br/>Select File]
    SelectFile1 --> FileValid1{File<br/>Selected?}
    FileValid1 -->|No| Warn1[Display Warning:<br/>No file selected]
    Warn1 --> SelectFile1
    FileValid1 -->|Yes| StoreFile1[Store File Path<br/>Extract Filename]
    
    StoreFile1 --> CipherChoice{User Selects<br/>Cipher Algorithm}
    
    %% CIPHER BRANCHES
    CipherChoice -->|AES-GCM| SetAES[Set cipher = AES-GCM<br/>Nonce: Required<br/>Key: 32 bytes]
    CipherChoice -->|ChaCha20| SetChaCha[Set cipher = ChaCha20<br/>Nonce: Required<br/>Key: 32 bytes]
    CipherChoice -->|AES-SIV| SetSIV[Set cipher = AES-SIV<br/>Nonce: None<br/>Key: 64 bytes]
    
    SetAES --> RunEncrypt[User Clicks RUN]
    SetChaCha --> RunEncrypt
    SetSIV --> RunEncrypt
    
    RunEncrypt --> StartThread[Create Processing Thread]
    StartThread --> VisualStart[Visual Status:<br/>Initializing quantum channel]
    
    %% BB84 PROTOCOL
    VisualStart --> BB84Start[BB84 QKD Protocol]
    
    BB84Start --> AliceGen[Alice Generates:<br/>1024 random bits<br/>Biased bases p_Z=0.8]
    AliceGen --> Channel[Quantum Channel:<br/>- Depolarizing noise 1.2%<br/>- Photon loss 3%<br/>- Dark counts 1%]
    Channel --> EveAttack{Eve Attack<br/>Enabled?}
    EveAttack -->|Yes 8%| EveIntercept[Eve intercepts<br/>Measures & Resends<br/>Introduces errors]
    EveAttack -->|No| BobMeasure
    EveIntercept --> BobMeasure[Bob Measures:<br/>Biased bases p_Z=0.8<br/>6 shots per qubit]
    
    BobMeasure --> BasisRecon[Basis Reconciliation:<br/>Public channel<br/>Keep matching bases]
    BasisRecon --> Sifting[Sifting:<br/>~667 bits remain<br/>from 1024 original]
    
    Sifting --> KeyConfirm[Key Confirmation:<br/>Sacrifice 20 bits<br/>Calculate QBER]
    KeyConfirm --> QBERCheck{QBER ≤ 15%?}
    
    QBERCheck -->|No QBER > 15%| AbortHigh[Display Error:<br/>High error rate detected<br/>Possible eavesdropping]
    AbortHigh --> EndAbort([STOP: Encryption Aborted])
    
    QBERCheck -->|Yes| PrivacyAmp[Privacy Amplification:<br/>Calculate ell secure length<br/>Truncate to 256 bits]
    
    PrivacyAmp --> SplitKeys[Key A: 256 bits Alice<br/>Key B: 256 bits Bob]
    
    %% HKDF KEY DERIVATION
    SplitKeys --> HKDF[HKDF Key Derivation]
    HKDF --> GenSalt[Generate 16-byte<br/>random salt]
    GenSalt --> HKDFExtract[HKDF-Extract:<br/>PRK = HMAC-SHA256 salt IKM]
    HKDFExtract --> HKDFExpand[HKDF-Expand:<br/>Generate encryption keys]
    
    HKDFExpand --> CipherBranch{Which Cipher<br/>Selected?}
    
    %% AES-GCM ENCRYPTION
    CipherBranch -->|AES-GCM| ReadFileAES[Read File Bytes]
    ReadFileAES --> GenNonceAES[Generate 12-byte<br/>random nonce]
    GenNonceAES --> PrepAAD_AES[Prepare AAD:<br/>version + filename + salt]
    PrepAAD_AES --> EncryptAES[AES-256-GCM Encryption:<br/>ciphertext + 16-byte tag]
    EncryptAES --> SignAES[Generate Dilithium5<br/>Signature 4595 bytes]
    SignAES --> PackageAES[Package JSON:<br/>version = AES-GCM-v1<br/>Include nonce]
    PackageAES --> SaveAES[Save as:<br/>filename_AES-GCM_E.bb84]
    SaveAES --> DisplayResultsEnc
    
    %% CHACHA20 ENCRYPTION
    CipherBranch -->|ChaCha20| ReadFileCC[Read File Bytes]
    ReadFileCC --> GenNonceCC[Generate 12-byte<br/>random nonce]
    GenNonceCC --> PrepAAD_CC[Prepare AAD:<br/>version + filename + salt]
    PrepAAD_CC --> EncryptCC[ChaCha20-Poly1305:<br/>Stream cipher + MAC<br/>ciphertext + 16-byte tag]
    EncryptCC --> SignCC[Generate Dilithium5<br/>Signature 4595 bytes]
    SignCC --> PackageCC[Package JSON:<br/>version = ChaCha20-v1<br/>Include nonce]
    PackageCC --> SaveCC[Save as:<br/>filename_CHACHA20_E.bb84]
    SaveCC --> DisplayResultsEnc
    
    %% AES-SIV ENCRYPTION
    CipherBranch -->|AES-SIV| ReadFileSIV[Read File Bytes]
    ReadFileSIV --> NoNonceSIV[NO Nonce Generation<br/>Deterministic mode]
    NoNonceSIV --> PrepAAD_SIV[Prepare AAD:<br/>version + filename + salt]
    PrepAAD_SIV --> EncryptSIV[AES-256-SIV Encryption:<br/>Generate SIV 16 bytes<br/>CTR mode encryption]
    EncryptSIV --> SignSIV[Generate Dilithium5<br/>Signature 4595 bytes]
    SignSIV --> PackageSIV[Package JSON:<br/>version = AES-SIV-v1<br/>nonce = null]
    PackageSIV --> SaveSIV[Save as:<br/>filename_AES-SIV_E.bb84]
    SaveSIV --> DisplayResultsEnc
    
    %% DISPLAY ENCRYPTION RESULTS
    DisplayResultsEnc[Display Results:<br/>QKD Stats QBER ell<br/>Encryption Success<br/>Show Key B]
    DisplayResultsEnc --> ShowButtons[Show Buttons:<br/>Copy Key B<br/>Save Key B to file]
    ShowButtons --> ExportMetrics[Export Metrics:<br/>bb84_metrics.json]
    ExportMetrics --> EncryptEnd([ENCRYPTION COMPLETE])
    
    %% DECRYPTION BRANCH
    ModeSelect -->|Decrypt| HideCipher[Hide Cipher Selector<br/>Show Key B Input]
    HideCipher --> SelectFile2[User Clicks<br/>Select File]
    SelectFile2 --> FileValid2{File<br/>Selected?}
    FileValid2 -->|No| Warn2[Display Warning:<br/>No file selected]
    Warn2 --> SelectFile2
    FileValid2 -->|Yes .bb84| StoreFile2[Store File Path<br/>Parse filename for cipher]
    
    StoreFile2 --> KeyInput{Key B<br/>Input Method?}
    KeyInput -->|Manual Paste| ValidateKey[Validate Key B:<br/>Only 0s and 1s<br/>Length = 256 bits]
    KeyInput -->|Import File| LoadKeyFile[Load .txt File<br/>Read Key B content]
    LoadKeyFile --> ValidateKey
    
    ValidateKey --> KeyValid{Key B<br/>Valid?}
    KeyValid -->|No| KeyError[Display Error:<br/>Invalid Key B format]
    KeyError --> KeyInput
    KeyValid -->|Yes| RunDecrypt[User Clicks RUN]
    
    RunDecrypt --> LoadPackage[Load .bb84 File<br/>Base64 decode<br/>Parse JSON]
    LoadPackage --> ExtractComponents[Extract:<br/>ciphertext salt nonce<br/>version filename<br/>signature public_key]
    
    ExtractComponents --> AutoDetect{Auto-Detect<br/>Cipher from<br/>Version Field}
    AutoDetect -->|AES-GCM-v1| DetectAES[cipher = AES-GCM<br/>has_nonce = True]
    AutoDetect -->|ChaCha20-v1| DetectCC[cipher = ChaCha20<br/>has_nonce = True]
    AutoDetect -->|AES-SIV-v1| DetectSIV[cipher = AES-SIV<br/>has_nonce = False]
    AutoDetect -->|Unknown| VersionError[Display Error:<br/>Unknown cipher version]
    VersionError --> DecryptEnd
    
    DetectAES --> VerifySig
    DetectCC --> VerifySig
    DetectSIV --> VerifySig
    
    VerifySig[Verify Dilithium5 Signature:<br/>VERIFY BEFORE DECRYPT]
    VerifySig --> SigValid{Signature<br/>Valid?}
    
    SigValid -->|No| SigError[Display Error:<br/>Invalid signature<br/>File tampered]
    SigError --> DecryptEnd([DECRYPTION FAILED])
    
    SigValid -->|Yes| DeriveKeyDec[Derive Key from Key B:<br/>HKDF with salt<br/>32 or 64 bytes]
    DeriveKeyDec --> RebuildAAD[Rebuild AAD:<br/>version + filename + salt]
    
    RebuildAAD --> DecryptBranch{Which Cipher<br/>Detected?}
    
    %% AES-GCM DECRYPTION
    DecryptBranch -->|AES-GCM| DecryptAES_D[AES-256-GCM Decryption:<br/>Verify 16-byte tag<br/>Decrypt with nonce]
    DecryptAES_D --> TagValidAES{AEAD Tag<br/>Valid?}
    TagValidAES -->|No| TagErrorAES[Display Error:<br/>AEAD authentication failed<br/>Wrong Key B or tampered]
    TagErrorAES --> DecryptEnd
    TagValidAES -->|Yes| ExtractPayload
    
    %% CHACHA20 DECRYPTION
    DecryptBranch -->|ChaCha20| DecryptCC_D[ChaCha20-Poly1305 Decryption:<br/>Verify Poly1305 MAC<br/>XOR with keystream]
    DecryptCC_D --> TagValidCC{Poly1305<br/>Valid?}
    TagValidCC -->|No| TagErrorCC[Display Error:<br/>MAC verification failed<br/>Wrong Key B or tampered]
    TagErrorCC --> DecryptEnd
    TagValidCC -->|Yes| ExtractPayload
    
    %% AES-SIV DECRYPTION
    DecryptBranch -->|AES-SIV| DecryptSIV_D[AES-256-SIV Decryption:<br/>Extract SIV<br/>CTR decrypt<br/>Verify SIV]
    DecryptSIV_D --> SIVValid{SIV<br/>Valid?}
    SIVValid -->|No| SIVError[Display Error:<br/>SIV authentication failed<br/>Wrong Key B or tampered]
    SIVError --> DecryptEnd
    SIVValid -->|Yes| ExtractPayload
    
    %% EXTRACT AND SAVE
    ExtractPayload[Extract Payload:<br/>Parse internal JSON<br/>Base64 decode file bytes]
    ExtractPayload --> RestoreFile[Restore Original File:<br/>filename + extension]
    RestoreFile --> AutoNameDec[Auto-generate filename:<br/>original_cipher_E_decrypted.ext]
    AutoNameDec --> SaveDecrypted[Save Decrypted File]
    SaveDecrypted --> DisplayResultsDec[Display Success:<br/>Decryption complete<br/>AEAD passed<br/>Signature verified]
    DisplayResultsDec --> UpdateMetricsDec[Update Metrics:<br/>Decryption time<br/>File hash]
    UpdateMetricsDec --> DecryptSuccess([DECRYPTION COMPLETE])
    
    %% METRICS REPORT
    EncryptEnd -.->|Optional| MetricsReport
    DecryptSuccess -.->|Optional| MetricsReport
    MetricsReport[User Clicks:<br/>Download Metrics Report PDF]
    MetricsReport --> LoadMetrics[Load bb84_metrics.json]
    LoadMetrics --> MetricsValid{Metrics<br/>Found?}
    MetricsValid -->|No| MetricsError[Display Error:<br/>Metrics file not found]
    MetricsValid -->|Yes| GenPDF[Generate PDF Report:<br/>All metrics + timestamps]
    GenPDF --> AutoNamePDF[Auto-generate filename:<br/>file_cipher_report_operation.pdf]
    AutoNamePDF --> SavePDF[Save PDF Report]
    SavePDF --> PDFEnd([PDF SAVED])
    
    MetricsError --> PDFEnd
    
    style Start fill:#90EE90
    style Init fill:#87CEEB
    style EncryptEnd fill:#FFD700
    style DecryptSuccess fill:#FFD700
    style EndAbort fill:#FF6B6B
    style DecryptEnd fill:#FF6B6B
    style PDFEnd fill:#DDA0DD
    
    style BB84Start fill:#FFA07A
    style HKDF fill:#FFA07A
    style EncryptAES fill:#98FB98
    style EncryptCC fill:#98FB98
    style EncryptSIV fill:#98FB98
    style DecryptAES_D fill:#87CEFA
    style DecryptCC_D fill:#87CEFA
    style DecryptSIV_D fill:#87CEFA
```

---

## Simplified High-Level Activity Diagram

```mermaid
flowchart TD
    Start([Start Application]) --> Mode{Select Mode}
    
    Mode -->|Encrypt| E1[Select File]
    Mode -->|Decrypt| D1[Select .bb84 File]
    
    E1 --> E2[Choose Cipher:<br/>AES-GCM / ChaCha20 / AES-SIV]
    E2 --> E3[Run BB84 QKD Protocol]
    E3 --> E4{QBER ≤ 15%?}
    E4 -->|No| E_Abort([Abort: Eavesdropping])
    E4 -->|Yes| E5[Derive Keys HKDF]
    E5 --> E6[Encrypt File AEAD]
    E6 --> E7[Sign with Dilithium5]
    E7 --> E8[Save .bb84 File]
    E8 --> E9[Display Key B]
    E9 --> E_End([Encryption Complete])
    
    D1 --> D2[Enter Key B]
    D2 --> D3[Load & Parse Package]
    D3 --> D4[Verify Signature FIRST]
    D4 --> D5{Signature Valid?}
    D5 -->|No| D_Abort([Abort: Tampered])
    D5 -->|Yes| D6[Derive Key from Key B]
    D6 --> D7[Decrypt & Verify AEAD]
    D7 --> D8{AEAD Tag Valid?}
    D8 -->|No| D_Fail([Fail: Wrong Key])
    D8 -->|Yes| D9[Extract Original File]
    D9 --> D10[Save Decrypted File]
    D10 --> D_End([Decryption Complete])
    
    style Start fill:#90EE90
    style E_End fill:#FFD700
    style D_End fill:#FFD700
    style E_Abort fill:#FF6B6B
    style D_Abort fill:#FF6B6B
    style D_Fail fill:#FF6B6B
```

---

## BB84 Protocol Detailed Subprocess

```mermaid
flowchart TD
    BB84_Start([BB84 QKD Protocol Start]) --> Step1[Alice: Generate 1024 random bits<br/>Choose biased bases p_Z=0.8]
    Step1 --> Step2[Prepare qubits in states:<br/>|0⟩ |1⟩ |+⟩ |−⟩]
    Step2 --> Step3[Quantum Channel Transmission]
    
    Step3 --> Noise[Apply Channel Noise:<br/>Depolarizing 1.2%<br/>Photon loss 3%<br/>Dark counts 1%]
    
    Noise --> Attack{Eve Attack?}
    Attack -->|8% fraction| Eve[Eve intercepts<br/>Measures random basis<br/>Resends qubits]
    Attack -->|92% fraction| Bob
    Eve --> Bob
    
    Bob[Bob: Measure qubits<br/>Biased bases p_Z=0.8<br/>6 shots per qubit]
    Bob --> Recon[Basis Reconciliation:<br/>Public channel<br/>Discard mismatched]
    
    Recon --> Sift[Sifting Result:<br/>~667 bits remain]
    Sift --> Sample[Sacrifice 20 bits<br/>Calculate QBER]
    
    Sample --> Check{QBER ≤ 15%?}
    Check -->|No| Abort([Abort Protocol])
    Check -->|Yes| Privacy[Privacy Amplification:<br/>Calculate ell ~379 bits<br/>Truncate to 256 bits]
    
    Privacy --> Output[Output:<br/>Key A 256 bits<br/>Key B 256 bits<br/>QBER statistics]
    Output --> BB84_End([BB84 Protocol Complete])
    
    style BB84_Start fill:#90EE90
    style BB84_End fill:#FFD700
    style Abort fill:#FF6B6B
    style Noise fill:#FFA07A
    style Eve fill:#FF6347
```

---

## Cipher Selection Decision Tree

```mermaid
flowchart TD
    Start([User Selects Cipher]) --> Choice{Which Cipher?}
    
    Choice -->|AES-GCM| AES_Config[Configuration:<br/>Algorithm: AES-256-GCM<br/>Key: 32 bytes<br/>Nonce: 12 bytes random<br/>Tag: 16 bytes<br/>Hardware: AES-NI<br/>Speed: 4-10 GB/s]
    
    Choice -->|ChaCha20| CC_Config[Configuration:<br/>Algorithm: ChaCha20-Poly1305<br/>Key: 32 bytes<br/>Nonce: 12 bytes random<br/>Tag: 16 bytes<br/>Hardware: None needed<br/>Speed: 500-800 MB/s]
    
    Choice -->|AES-SIV| SIV_Config[Configuration:<br/>Algorithm: AES-256-SIV<br/>Key: 64 bytes two keys<br/>Nonce: NONE deterministic<br/>Tag: 16 bytes SIV<br/>Hardware: Software<br/>Misuse-resistant: YES]
    
    AES_Config --> AES_Use[Use Case:<br/>Desktop/Server<br/>Intel/AMD with AES-NI<br/>High throughput]
    
    CC_Config --> CC_Use[Use Case:<br/>Mobile/ARM/Embedded<br/>No AES-NI available<br/>Constant-time security]
    
    SIV_Config --> SIV_Use[Use Case:<br/>Research/High-security<br/>Nonce management difficult<br/>Deterministic encryption]
    
    AES_Use --> Proceed[Proceed to Encryption]
    CC_Use --> Proceed
    SIV_Use --> Proceed
    
    Proceed --> End([Continue to HKDF])
    
    style Start fill:#90EE90
    style End fill:#FFD700
    style AES_Config fill:#87CEEB
    style CC_Config fill:#98FB98
    style SIV_Config fill:#DDA0DD
```

---

## Error Handling Flow

```mermaid
flowchart TD
    Start([Operation in Progress]) --> Error{Error Type?}
    
    Error -->|Wrong Key B| E1[AEAD Tag Verification Fails]
    E1 --> E1_Msg[Display:<br/>Decryption failed<br/>Wrong Key B or tampered file]
    E1_Msg --> E1_End([Stop Decryption])
    
    Error -->|Tampered File| E2[Signature Verification Fails]
    E2 --> E2_Msg[Display:<br/>Invalid signature<br/>File tampered]
    E2_Msg --> E2_End([Stop Decryption<br/>No decryption attempted])
    
    Error -->|High QBER| E3[QBER > 15% Threshold]
    E3 --> E3_Msg[Display:<br/>High error rate<br/>Possible eavesdropping<br/>Encryption aborted]
    E3_Msg --> E3_End([Stop Encryption])
    
    Error -->|Invalid Format| E4[JSON Parse Fails or<br/>Version Unknown]
    E4 --> E4_Msg[Display:<br/>Invalid package format<br/>Unknown cipher version]
    E4_Msg --> E4_End([Stop Operation])
    
    Error -->|No File| E5[File Path Empty]
    E5 --> E5_Msg[Display:<br/>No file selected<br/>Please select a file]
    E5_Msg --> E5_Retry[Return to File Selection]
    
    style Start fill:#90EE90
    style E1_End fill:#FF6B6B
    style E2_End fill:#FF6B6B
    style E3_End fill:#FF6B6B
    style E4_End fill:#FF6B6B
    style E5_Retry fill:#FFD700
```

---

## HKDF Key Derivation Subprocess

```mermaid
flowchart TD
    Start([HKDF Key Derivation]) --> Input[Input:<br/>BB84 Key A 256 bits<br/>Random Salt 16 bytes]
    
    Input --> Extract[HKDF-Extract Phase:<br/>PRK = HMAC-SHA256 salt IKM]
    Extract --> PRK[Pseudorandom Key PRK<br/>32 bytes 256 bits]
    
    PRK --> Expand[HKDF-Expand Phase]
    Expand --> Branch{Cipher Type?}
    
    Branch -->|AES-GCM/ChaCha20| Expand32[Expand to 32 bytes:<br/>info = encryption_key<br/>length = 32]
    Branch -->|AES-SIV| Expand64[Expand to 64 bytes:<br/>info = encryption_key<br/>length = 64]
    
    Expand32 --> Keys32[Output:<br/>Encryption Key: 32 bytes<br/>Auth Key: 32 bytes optional<br/>Signature Key: Dilithium5]
    
    Expand64 --> Keys64[Output:<br/>Encryption Key: 64 bytes<br/>two 256-bit keys<br/>Signature Key: Dilithium5]
    
    Keys32 --> End([Keys Ready for Encryption])
    Keys64 --> End
    
    style Start fill:#90EE90
    style End fill:#FFD700
    style Extract fill:#87CEEB
    style Expand fill:#98FB98
```

---

## Rendering Instructions

### For GitHub:
1. Copy this entire file to your repository
2. GitHub will automatically render Mermaid diagrams
3. View the file in GitHub's web interface

### For Local Rendering:
**Option 1: VS Code**
```bash
# Install Mermaid extension
code --install-extension bierner.markdown-mermaid
```

**Option 2: Online Mermaid Editor**
- Visit: https://mermaid.live/
- Copy any diagram code block
- Paste and edit in real-time

**Option 3: Export as PNG/SVG**
```bash
# Install Mermaid CLI
npm install -g @mermaid-js/mermaid-cli

# Generate PNG
mmdc -i ACTIVITY_DIAGRAM.md -o activity_diagram.png

# Generate SVG
mmdc -i ACTIVITY_DIAGRAM.md -o activity_diagram.svg
```

---

## Diagram Legend

### Node Types:
- **Rounded Rectangle** `([text])` = Start/End points
- **Rectangle** `[text]` = Process/Action
- **Diamond** `{text?}` = Decision point
- **Parallelogram** (styled) = Input/Output
- **Hexagon** (styled) = Subprocess

### Color Coding:
- 🟢 **Green** = Start points
- 🟡 **Gold** = Successful completion
- 🔴 **Red** = Error/Abort endpoints
- 🔵 **Blue** = Process nodes
- 🟣 **Purple** = Optional operations
- 🟠 **Orange** = Subprocesses

### Arrow Types:
- **Solid line** `-->` = Normal flow
- **Dashed line** `-.->` = Optional/Conditional flow

---

## Notes

1. **Main Diagram** shows complete end-to-end flow with all three cipher branches
2. **Simplified Diagram** shows high-level overview without technical details
3. **BB84 Subprocess** shows detailed quantum protocol steps
4. **Cipher Decision Tree** shows configuration for each encryption mode
5. **Error Handling** shows all error paths and recovery logic
6. **HKDF Subprocess** shows key derivation process

All diagrams are fully functional Mermaid syntax and can be:
- Rendered in GitHub/GitLab
- Exported to PNG/SVG/PDF
- Edited in Mermaid Live Editor
- Embedded in documentation

---

**File Status:** ✅ Ready for rendering
**Total Diagrams:** 6 comprehensive activity diagrams
**Format:** Mermaid flowchart syntax
**Compatibility:** GitHub, GitLab, VS Code, Mermaid Live Editor
