# ePassport Forensic Verifier 🛂🔍

An open-source forensic tool for analyzing and verifying Electronic Machine Readable Travel Documents (eMRTD) compliant with **ICAO Doc 9303**.

This project implements a full **Passive Authentication** pipeline, capable of handling standard cryptographic curves (e.g., European passports) and detecting interoperability anomalies in non-standard implementations (e.g., Vietnamese explicit parameters).

## 🚀 Features

* **NFC Extraction:** Secure communication via PC/SC reader (APDU/BAC) to dump DG1, DG2, and SOD.
* **Passive Authentication:**
    * **Integrity:** Hash verification of Data Groups (SHA-256/SHA-512).
    * **Authenticity:** Digital signature verification (RSA-PSS, ECDSA).
    * **Trust Chain:** Full validation against Country Signing Certification Authority (CSCA).
    * **Revocation:** Check against Certificate Revocation Lists (CRL).
* **Forensic Analysis Module:** Specific workflow to handle and analyze "Explicit Curve Parameters" anomalies (Error 94 in OpenSSL) often found in non-standard PKI implementations.

## 📂 Project Structure

```text
ePassport-Verifier/
├── src/                    # Standard verification engine
│   ├── scan.py             # NFC Data Extraction tool
│   └── verify.py           # Passive Authentication & Reporting logic
│
├── forensics_vietnam/      # Case Study: Interoperability Analysis
│   ├── extract_from_ml.py  # CSCA extraction from Master Lists
│   ├── prepare_sod.py      # Binary cleaning for raw SOD files
│   └── run_analysis.sh     # Bash automation for OpenSSL forensic checks
│
├── data/                   # Data storage
│   ├── certs/              # CSCA Certificates and CRLs
│   └── dumps/              # Extracted binaries (SOD, DG1, DG2)
│
└── requirements.txt        # Python dependencies

```

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone [https://github.com/Simolaaaab/ePassport-Verifier.git](https://github.com/Simolaaaab/ePassport-Verifier.git)
cd ePassport-Verifier

```


2. **Install dependencies:**
```bash
pip install -r requirements.txt

```


*Note: A PC/SC Smart Card reader driver (e.g., `pcscd`) is required for scanning.*

## 📖 Usage

### 1. Standard Verification (e.g., Italian Passport)

Edit `src/scan.py` with the correct MRZ (Machine Readable Zone) key to unlock the chip.

```bash
# Step 1: Scan and Dump Data
python3 src/scan.py

# Step 2: Verify Integrity and Trust
python3 src/verify.py

```

### 2. Forensic Case Study: The Vietnam Anomaly

This module analyzes a known interoperability issue where the Document Signer (DS) certificate uses **Explicit ECC Parameters** (violating RFC 5480 best practices), causing standard verification failures.

```bash
cd forensics_vietnam
chmod +x run_analysis.sh
./run_analysis.sh

```

**Output Analysis:**

* **Step 1 (Integrity):** `openssl cms -noverify` -> **SUCCESS** (Proves the document is unaltered).
* **Step 2 (Trust):** `openssl verify` -> **FAIL (Error 94)** (Proves non-compliance with modern security policies).

## 📜 Requirements

* Python 3.8+
* OpenSSL (for forensic scripts)
* Smart Card Reader (for scanning)

## 🎓 Context

Developed as part of a university project on **PKI & ePassport Security**. The tool highlights the challenges of global interoperability in digital border control systems.
