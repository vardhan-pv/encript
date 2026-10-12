# DES Vault — Universal File Encryption & Decryption System

[![DES](https://img.shields.io/badge/Algorithm-DES%20(FIPS%2046--3)-06b6d4?style=flat-square)](#des-algorithm-implementation)
[![Block-Size](https://img.shields.io/badge/Block%20Size-64--bit-blue?style=flat-square)](#)
[![Key-Size](https://img.shields.io/badge/Effective%20Key-56--bit-amber?style=flat-square)](#)
[![Container](https://img.shields.io/badge/Container-.dvlt%20(v1.0)-10b981?style=flat-square)](#dvlt-binary-container-specification)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](#)

> **Academic Security Notice:** DES is implemented strictly for educational, academic, and demonstration purposes. DES utilizes a 56-bit effective key and is obsolete for modern production environments. It is implemented here from first principles according to the FIPS 46-3 specification to analyze Feistel networks, bitwise permutations, S-box non-linearity, and container integrity verification.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [System Architecture](#system-architecture)
4. [Technology Stack](#technology-stack)
5. [DES Algorithm Implementation](#des-algorithm-implementation)
6. [Encryption & Decryption Pipelines](#encryption--decryption-pipelines)
7. [`.dvlt` Binary Container Specification](#dvlt-binary-container-specification)
8. [File DNA & Cryptographic Telemetry](#file-dna--cryptographic-telemetry)
9. [DES Lab & Visualizers](#des-lab--visualizers)
10. [Installation & Local Execution](#installation--local-execution)
11. [Automated Verification & Testing](#automated-verification--testing)
12. [Security Limitations](#security-limitations)
13. [Future Improvements](#future-improvements)

---

## 1. Project Overview

**DES Vault** is a universal file encryption and decryption application implementing the actual **Data Encryption Standard (DES / FIPS 46-3)** on arbitrary binary files. Unlike traditional text-only encryption demonstrations, DES Vault treats all uploaded files as raw `Uint8Array` binary streams, enabling byte-for-byte exact round-trip encryption and restoration for:

- **Documents**: PDF, DOCX, DOC, TXT, CSV, XLS, XLSX, PPT, PPTX
- **Images**: PNG, JPG, JPEG, WEBP, GIF, SVG, BMP
- **Media**: MP3, WAV, MP4, AAC
- **Archives**: ZIP, TAR, GZ, 7Z
- **Source Code**: Java, Python, JavaScript, HTML, CSS, SQL, C/C++
- **Generic Binary Payloads**: Executables, byte dumps, raw blobs

The application features a modern dark cybersecurity dashboard ("Digital Cryptography Vault"), client-side zero-server execution ("Private Mode"), an interactive Feistel round inspector, an ECB vs. CBC visual security experiment, and SHA-256 integrity checksum verification.

---

## 2. Key Features

- **True Universal Binary Support**: Processes binary byte buffers (`ArrayBuffer` / `Uint8Array`) without string conversions or encoding corruption.
- **Custom `.dvlt` Binary Container**: Enforces structured container formatting containing magic bytes (`DVLT`), versioning, cipher mode ID, random IV, original SHA-256 fingerprint, JSON file metadata, and ciphertext.
- **Strict Key Management**:
  - 8-Character ASCII Text Keys
  - 16-Digit Hexadecimal Keys
  - Passphrase-derived Keys via PBKDF2 with SHA-256
  - Cryptographically secure pseudorandom key generation (`crypto.getRandomValues`)
  - Keyfile Export (`.deskey`) with security warning
  - Key transfer QR code generator
- **Cipher Modes**:
  - **DES-CBC (Cipher Block Chaining)**: Recommended mode with a fresh random 8-byte IV per container.
  - **DES-ECB (Electronic Codebook)**: Academic comparison mode illustrating identical block leakage.
- **PKCS#7 Padding**: Strict padding (1 to 8 bytes) and unpadding with corruption detection.
- **Integrity Verification**: Automatic post-decryption SHA-256 recalculation against the container fingerprint.
- **File DNA Telemetry**: Real-time Shannon entropy calculation (0.000 to 8.000 bits/byte), block count, padding estimation, and byte-frequency histograms.
- **DES Lab**:
  - 16-Round Feistel Network visualizer with expandable rounds showing Expansion $E(R)$, subkey $K_i$, 8 S-box substitutions (row/col breakdown), and $P$-permutation.
  - Key Schedule trace (PC-1, $C_0/D_0$ shifts, PC-2, 16 subkeys).
  - ECB vs. CBC live identical-block leakage experiment.
- **Examiner Demo Mode ("Demo DES")**: 1-click guided presentation wizard walking examiners through sample selection, inspection, encryption, wrong-key rejection, and verified restoration.
- **100% Client-Side Private Mode**: Files and keys never leave the user's browser.

---

## 3. System Architecture

```
DES_Encryption_Decryption_App/
├── dist/
│   ├── crypto/
│   │   └── des/
│   │       ├── constants.js       # FIPS 46-3 Tables: IP, FP, E, P, PC-1, PC-2, SHIFTS, 8 S-Boxes
│   │       ├── keySchedule.js     # PC-1 parity stripping, 28-bit C/D registers, shifts, PC-2 48-bit subkeys
│   │       ├── feistel.js         # Precomputed S-P table, F(R, K) Feistel function, round telemetry
│   │       ├── desCore.js         # 64-bit block encryption/decryption, educational 16-round tracer
│   │       ├── modes.js           # DES-CBC with random IV, DES-ECB, streaming progress yielding
│   │       ├── padding.js         # PKCS#7 block padding and strict unpadding validation
│   │       ├── container.js       # .dvlt binary format creation, header inspection, sanitization
│   │       ├── hash.js            # Universal Web Crypto & Node SHA-256 checksum utility
│   │       ├── entropy.js         # Shannon entropy calculation & byte distribution
│   │       └── testVectors.js     # Automated test suite (FIPS 46-3, KATs, round-trips)
│   ├── services/
│   │   ├── historyManager.js      # Safe audit log (never logs keys or file payloads)
│   │   ├── keyManager.js          # ASCII/Hex parsing, CSPRNG generation, PBKDF2 derivation, .deskey export
│   │   ├── samples.js             # Pre-packaged sample files (PDF, PNG, ZIP, TXT)
│   │   └── qrGenerator.js         # Standalone SVG QR matrix renderer for key transfer
│   ├── index.html                 # Semantic HTML5 single-page application with accessible views
│   ├── style.css                  # Modern dark cybersecurity design system (CSS variables, glow, typography)
│   ├── app.js                     # Main application controller, UI event bindings, and pipelines
│   └── favicon.svg                # Application vector icon
├── verify.mjs                     # Automated verification test script
├── start_windows.bat              # 1-Click local Windows Python server launcher
└── README.md                      # Comprehensive academic documentation
```

---

## 4. Technology Stack

- **Core**: Vanilla ECMAScript (ES2022+ Modules) — Zero compile or bundling step required.
- **Cryptography**: Pure JavaScript implementation of DES (FIPS 46-3) with precomputed SP optimization tables; Web Crypto API for CSPRNG (`crypto.getRandomValues`) and SHA-256 (`crypto.subtle.digest`).
- **Styling**: Vanilla CSS3 with custom properties, glassmorphism, responsive CSS Grid, and flexbox.
- **Typography**: Inter (UI / Text) & JetBrains Mono (Cryptographic hex, binary bits, registers).
- **Environment**: Cross-platform (Chrome, Edge, Firefox, Safari; Node.js 20+; Python 3+).

---

## 5. DES Algorithm Implementation

The DES implementation follows the National Institute of Standards and Technology **FIPS PUB 46-3** standard:

1. **Initial Permutation (IP)**: Permutes 64 input bits into left ($L_0$) and right ($R_0$) 32-bit registers.
2. **Key Schedule**:
   - 64-bit key input $\rightarrow$ **PC-1** drops parity bits (8, 16, 24, 32, 40, 48, 56, 64) to form a 56-bit key.
   - Split into two 28-bit halves: $C_0$ and $D_0$.
   - For rounds $1, 2, 9, 16$: 1-bit left circular shift; for other rounds: 2-bit left circular shift.
   - **PC-2** selects 48 bits from the 56 shifted bits to generate subkey $K_i$.
3. **Feistel Function $F(R_{i-1}, K_i)$**:
   - **Expansion ($E$)**: Expands 32-bit $R_{i-1}$ to 48 bits.
   - **Key XOR**: 48-bit expanded output is XORed with 48-bit subkey $K_i$.
   - **S-Boxes ($S_1 \dots S_8$)**: The 48 bits are divided into eight 6-bit chunks. Each 6-bit chunk addresses a $4 \times 16$ S-box (bits 1 and 6 define the row $0..3$; bits 2..5 define the column $0..15$) yielding a 4-bit output.
   - **Permutation ($P$)**: The 32 bits from all 8 S-boxes are permuted.
4. **Feistel Round Combination**:
   $$L_i = R_{i-1}$$
   $$R_i = L_{i-1} \oplus F(R_{i-1}, K_i)$$
5. **Final Permutation (FP / $\text{IP}^{-1}$)**: After 16 rounds, the 32-bit halves are swapped $(R_{16}, L_{16})$ and passed through FP to yield the 64-bit ciphertext block.
6. **Decryption Symmetry**: Block decryption applies the exact same Feistel rounds, reversing the subkey order ($K_{16}$ down to $K_1$).

---

## 6. Encryption & Decryption Pipelines

### Encryption Pipeline
```
Original File (Binary Bytes)
        ↓
Compute SHA-256 Fingerprint & Shannon Entropy
        ↓
Validate / Derive 8-Byte DES Key
        ↓
Generate 8-Byte Random IV (CBC Mode)
        ↓
Apply PKCS#7 Padding (8-byte alignment)
        ↓
Run 16 Feistel Rounds per 64-bit Block
        ↓
Assemble .dvlt Container (Header + Metadata + Ciphertext)
        ↓
Download Encrypted File (.dvlt)
```

### Decryption Pipeline
```
Upload Encrypted Container (.dvlt)
        ↓
Validate "DVLT" Magic Signature & Version 1
        ↓
Extract Mode, IV, Original SHA-256 & Filename
        ↓
Enter Matching 8-Byte DES Key (or load .deskey)
        ↓
Run 16 Reversed Feistel Rounds per Block
        ↓
Strip & Validate PKCS#7 Padding
        ↓
Recalculate SHA-256 on Restored Plaintext
        ↓
Verify Fingerprint Match (Integrity Check)
        ↓
Download / Preview Restored Original File
```

---

## 7. `.dvlt` Binary Container Specification

Files encrypted with DES Vault receive the `.dvlt` extension. The container layout is structured as follows:

| Byte Offset | Length | Field | Description |
|---|---|---|---|
| `0x00 - 0x03` | 4 bytes | Magic Bytes | ASCII `'DVLT'` (`0x44 0x56 0x4C 0x54`) |
| `0x04` | 1 byte | Version | Container version (`0x01`) |
| `0x05` | 1 byte | Algorithm ID | Cipher identifier (`0x01` = Single DES FIPS 46-3) |
| `0x06` | 1 byte | Mode ID | `0x01` = DES-CBC, `0x02` = DES-ECB |
| `0x07 - 0x0E` | 8 bytes | Initialization Vector | Random IV for CBC; 8 zero bytes for ECB |
| `0x0F - 0x2E` | 32 bytes | Original SHA-256 | Raw binary SHA-256 checksum of plaintext file |
| `0x2F - 0x32` | 4 bytes | Metadata Length | Big-Endian `UInt32` length $N$ of JSON metadata |
| `0x33 - 0x33+N-1`| $N$ bytes | Metadata JSON | UTF-8 JSON: `filename`, `mimeType`, `originalSize`, `timestamp` |
| `0x33+N - EOF` | Variable | Ciphertext | PKCS#7-padded DES ciphertext blocks |

> **Security Rule:** The DES encryption key is **NEVER** stored inside the `.dvlt` container.

---

## 8. File DNA & Cryptographic Telemetry

For every uploaded file, DES Vault calculates comprehensive **File DNA**:
- **SHA-256 Fingerprint**: 256-bit cryptographic hash for post-decryption tamper verification.
- **Shannon Entropy**: Evaluates randomness on a $0.000$ to $8.000$ scale:
  $$H(X) = -\sum_{i=0}^{255} p(i) \log_2 p(i)$$
- **Block Calculation**: Computes exact number of 64-bit blocks and PKCS#7 padding bytes required before encryption.
- **Hex Dump**: Interactive 256-byte hex inspector displaying byte offsets, hex pairs, and printable ASCII.

---

## 9. DES Lab & Visualizers

The dedicated **DES Lab** provides three educational modules:
1. **16-Round Feistel Network Visualizer**: Traces 64-bit blocks through IP, rounds 1 to 16, S-box substitutions, P-permutation, and FP.
2. **Key Schedule Visualizer**: Traces 64-bit key, PC-1 permutation, $C$ and $D$ register left-shift schedule, and PC-2 subkeys $K_1 \dots K_{16}$.
3. **ECB vs. CBC Security Experiment**: Live comparison of encrypting two identical blocks (`ATTACKAT` and `ATTACKAT`), proving how CBC eliminates identical block patterns.

---

## 10. Installation & Local Execution

### Option A: Using Windows Batch Script (Fastest)
1. Double-click `start_windows.bat`.
2. Open `http://localhost:8000` in your browser.

### Option B: Using Python Local Server
```bash
python -m http.server 8000 --bind 127.0.0.1 --directory dist
```

---

## 11. Automated Verification & Testing

```bash
# Run verification tests in Node.js:
node verify.mjs
```

All 9 test suites verify FIPS 46-3 test vectors, strict key validation, PDF/PNG/ZIP/TXT binary round trips, PKCS#7 padding, tamper resistance, and a 128 KiB high-throughput performance benchmark.
