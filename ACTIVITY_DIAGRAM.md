# BB84 Quantum Encryption Tool - Activity Diagram

## Complete System Activity Diagram

This document contains Mermaid activity diagrams for the BB84 Quantum Encryption Tool showing all decision points, processes, and cipher branches.

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
```

---

## BB84 Protocol Detailed Subprocess

```mermaid
flowchart TD
    BB84_Start([BB84 QKD Protocol Start]) --> Step1[Alice: Generate 1024 random bits<br/>Choose biased bases p_Z=0.8]
    Step1 --> Step2[Prepare qubits in states:<br/>0, 1, plus, minus]
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
```

---

## HKDF Key Derivation Subprocess

```mermaid
flowchart TD
    Start([HKDF Key Derivation]) --> Input[Input:<br/>BB84 Key A 256 bits<br/>Random Salt 16 bytes]
    
    Input --> Extract[HKDF-Extract Phase:<br/>PRK = HMAC-SHA256]
    Extract --> PRK[Pseudorandom Key PRK<br/>32 bytes]
    
    PRK --> Expand[HKDF-Expand Phase:<br/>Generate multiple keys]
    
    Expand --> Split[Split PRK into 3 parts]
    
    Split --> Key1[Part 1: Encryption Key<br/>32 or 64 bytes<br/>Based on cipher type]
    Split --> Key2[Part 2: Authentication Key<br/>32 bytes<br/>For AEAD operations]
    Split --> Key3[Part 3: Signature Key<br/>Variable size<br/>For Dilithium5]
    
    Key1 --> Combine[Combine All Keys]
    Key2 --> Combine
    Key3 --> Combine
    
    Combine --> Final{Cipher<br/>Requires?}
    
    Final -->|32 bytes| Output32[Total: 96+ bytes<br/>Encryption: 32<br/>Auth: 32<br/>Signature: variable]
    Final -->|64 bytes| Output64[Total: 128+ bytes<br/>Encryption: 64<br/>Auth: 32<br/>Signature: variable]
    
    Output32 --> End([Keys Ready for Use])
    Output64 --> End
```

---

## Rendering Instructions

### For GitHub:
1. Copy this file to your repository
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

### Arrow Types:
- **Solid line** `-->` = Normal flow
- **Dashed line** `-.->` = Optional/Conditional flow

---

## Diagram Summary

1. **Simplified High-Level** - Overview of encryption and decryption flows
2. **BB84 Protocol Subprocess** - Detailed 8-step quantum key distribution
3. **Cipher Selection Decision Tree** - Configuration for each encryption mode
4. **Error Handling Flow** - All error paths and recovery logic
5. **HKDF Subprocess** - Key derivation process

All diagrams use standard Mermaid syntax compatible with GitHub rendering.

---

**File Status:** ✅ Ready for rendering
**Total Diagrams:** 5 activity diagrams
**Format:** Mermaid flowchart syntax
**Compatibility:** GitHub, GitLab, VS Code, Mermaid Live Editor
