# Basic File Information Gathering Script 🚀

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![LIEF](https://img.shields.io/badge/LIEF-Parser-orange.svg)](https://lief.quarkslab.com/)

A versatile Python tool to extract comprehensive metadata and characteristics from files. Perfect for **malware analysts**, **digital forensics investigators**, and **SOC engineers**.

---

## 🔍 Features

- **Cryptographic Hashes**: MD5, SHA-1, SHA-256
- **Entropy Analysis**: Shannon entropy to detect packing/encryption
- **Permissions**: Human-readable UNIX file permissions
- **PE Metadata**: Compilation timestamp, compiler/runtime, import hash, header offset, entry point
- **Magic Number Detection**: Recognize 50+ common file types (PDF, PNG, ZIP, EXE, ELF, etc.)
- **Digital Signatures**: Parse and report certificate details (subject, issuer, validity)
- **Packer Heuristics**: Section entropy and name-based detection
- **Clean Output**: ANSI‑free, well‑aligned table for CLI

---

## 📦 Installation

Download the script and install dependencies:

```bash
# Download the latest version
curl -O https://raw.githubusercontent.com/anpa1200/Malware_analysis/main/Basic_inf_gathering.py

# (Optional) Clone the repository to get examples and LICENSE
git clone https://github.com/anpa1200/Malware_analysis.git && cd Malware_analysis

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install lief
# For digital signature parsing
pip install cryptography
```

---

## 🚀 Usage

```bash
python3 Basic_inf_gathering.py <path_to_file>
```

- `<path_to_file>`: Local path to the file you wish to analyze.
- Output: Detailed table printed to **stdout**.

---

## 📖 Function Reference

| Function                            | Description                                                       |
| ----------------------------------- | ----------------------------------------------------------------- |
| `calculate_hash(file, hash_func)`   | Compute file hash (MD5/SHA-1/SHA-256) in 4KB chunks.             |
| `calculate_entropy(file)`           | Shannon entropy calculation (detects high entropy).               |
| `get_file_permissions(file)`        | UNIX-style human-readable permissions.                            |
| `get_pe_timestamp(file)`            | Extract and validate PE compile timestamp via LIEF.               |
| `detect_compiler_and_language(file)`| Infer compiler/runtime from imports and section names.            |
| `get_magic_number(file, n)`         | Read first `n` bytes and return hex string.                       |
| `check_filetype_from_magic(file)`   | File type lookup against 50+ magic signatures.                    |
| `check_digital_signature(file)`     | Parse PE certificates (subject, issuer, validity).                |
| `calculate_imphash(file)`           | Compute PE imphash (import hash) for malware triage.             |
| `get_pe_header_offset(file)`        | Read DOS header `0x3C` pointer to PE header.                      |
| `get_entry_point(file)`             | Retrieve RVA & VA of entry point from Optional Header.            |
| `detect_packing(file)`              | Packer detection via entropy & name heuristics.                   |
| `print_beautiful(info)`             | Print formatted table of collected info.                         |
| `get_file_info(file)`               | Master function that orchestrates all analyses.                   |

---

## 🛠️ Examples

```bash
$ python3 Basic_inf_gathering.py samples/malicious.exe

================================================================================
                         📄 FILE INFORMATION SUMMARY 📄                             
================================================================================
File Name            : malicious.exe
File Path            : /home/user/samples/malicious.exe
Import Hash          : abcdef1234567890abcdef1234567890
MD5                  : 0123456789abcdef0123456789abcdef
SHA-1                : fedcba9876543210fedcba9876543210fedcba98
SHA-256              : ...
File Size            : 1.23 MB
Magic Number         : 4D5A9000
File Type            : Windows Executable (EXE)
Entropy              : 6.12 (✅ Normal)
Permissions          : -rwxr--r--
PE Timestamp         : 2020-05-10 12:34:56 UTC (✅ Legit)
Compiler & Language  : MSVC (Microsoft Visual C++)
Digital Signature    :
    • Subject Org.: Example Corp
    • Issuer Org. : Example CA
    • Validity    : 2020-01-01 → 2022-01-01 (Expired)
PE Header Offset     : 128 (0x80)
Entry Point          : RVA: 0x1200, VA: 0x401200
Packer Detection     : Unpacked
================================================================================
```

---

## 🔗 Dependencies

- **Python** 3.7+
- **LIEF**: `pip install lief`
- **cryptography** *(optional for signatures)*: `pip install cryptography`

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create a feature branch
3. Submit a Pull Request

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

