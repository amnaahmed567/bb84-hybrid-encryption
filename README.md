
# BB84 Hybrid Encryption Simulator

A **Python-based quantum-classical hybrid encryption system** combining:

- **Simulated BB84 Quantum Key Distribution (QKD)**
- **Authenticated Classical Encryption**: AES-GCM, ChaCha20-Poly1305, AES-SIV
- **Post-Quantum Digital Signatures**: Dilithium5
- **Graphical User Interface (GUI)** for file selection, encryption, and visualization

This framework demonstrates **quantum-aware cryptography** suitable for research, education, and secure file transmission.

---

## Features

- **Quantum Key Generation** with realistic channel noise, photon loss, and eavesdropping simulation
- **Multiple Encryption Options**: AES-GCM, ChaCha20-Poly1305, AES-SIV
- **Post-Quantum Integrity**: Dilithium5 signatures ensure authenticity and early tamper detection
- **HKDF-Based Key Separation**: Secure derivation of encryption, authentication, and signature keys
- **AEAD Encryption**: Metadata authentication and fail-fast error handling
- **GUI Visualization**: Real-time BB84 key simulation, encryption progress, and metric logging
- **Performance Logging**: JSON and PDF exports for auditing and reproducibility

---

## Repository Structure

```
BB84-Quantum-Encryption-Tool-Simulator/
├── start_gui.py                # Launches the desktop GUI
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
├── LICENSE                     # License file
├── bb84_metrics.json           # Metrics artifact (usage data)
├── gui/
│   └── bb84_gui.py             # GUI implementation (Tkinter)
├── bb84_backend/
│   ├── common/
│   │   └── common.py           # Shared utilities
│   ├── core/
│   │   ├── bb84_quantum.py     # BB84 simulation logic
│   │   ├── encryption.py       # Hybrid encryption workflows
│   │   ├── aes_engine.py       # AES-specific operations
│   │   └── key_utils.py        # Key derivation helpers
│   ├── logic/
│   │   └── controller.py       # Orchestrates QKD + encryption + packaging
│   └── secure_io/
│       ├── secure_packager.py  # AES-GCM packager
│       ├── secure_packager_chacha20.py # ChaCha20 packager
│       └── secure_packager_aes_siv.py  # AES-SIV packager (pending compression)
├── BB84_Test_Results/          # Sample test inputs, outputs, and screenshots
├── bundle/                     # Build/package artifacts
├── ACTIVITY_DIAGRAM.md         # Workflow diagram
└── docs/                       # Screenshots and diagrams for documentation
```

---

## Features (Detailed)

- Simulated **BB84 QKD** with:
  - Depolarizing noise
  - Photon loss
  - Biased basis selection
  - Partial intercept-resend attacks
- **Multiple encryption options**:
  - **AES-GCM**: Authenticated encryption with confidentiality and integrity
  - **ChaCha20-Poly1305**: Stream cipher optimized for ARM/mobile platforms
  - **AES-SIV**: Deterministic, misuse-resistant, nonce-free AEAD
- **Post-quantum Dilithium5 digital signatures** for tamper-resistant verification
- **HKDF-based key separation** for encryption, authentication, and signatures
- GUI provides:
  - File selection / drag-and-drop
  - Encryption mode selection
  - Real-time progress and logs
  - Key B display / copy
- Metrics logging (JSON/PDF) for auditability
- Fail-fast security with multi-layer tamper detection

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<username>/BB84-Quantum-Encryption-Tool-Simulator.git
cd BB84-Quantum-Encryption-Tool-Simulator
```

2. Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.10+ (tested on 3.12).

---

## Usage

### Launch GUI

```powershell
python start_gui.py
```

1. Select a file to encrypt (or drag-and-drop).
2. Choose an encryption mode: AES-GCM, ChaCha20-Poly1305, or AES-SIV.
3. Click **Run** to perform BB84 key simulation + encryption.
4. Save the `.bb84` package and copy Key B for decryption.

### Decrypt a file

1. Load a `.bb84` file in the GUI.
2. Paste or provide the corresponding Key B.
3. Click **Decrypt** to restore the original file.

Audit trail and logs are generated automatically in the GUI console and `bb84_metrics.json`.

---

## Test Results

The `BB84_Test_Results/` folder contains:

- Screenshots of encryption/decryption for various file types (text, audio, video, images, PDFs)
- Metrics reports (JSON/PDF) for validation and reproducibility

The test results demonstrate:

- Correct restoration of file sizes
- Multi-layer integrity checking
- Handling of wrong keys, corrupted metadata, and AEAD failures


## License

This project is licensed under the MIT License 

---

## Acknowledgements

- Qiskit — Quantum simulation inspiration
- NIST Post-Quantum Cryptography Project — PQC standards reference


