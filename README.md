# Basic File Information Gathering Script

File triage for malware analysts and CTI engineers: hashes, metadata, strings, entropy, YARA context, and static characteristics that become IOC enrichment and detection leads.

## CTI Use

Use this as the first-pass file triage layer before deeper reverse engineering. The output helps answer: what is the file, what indicators does it expose, does it look packed or unusual, and what should be pivoted or hunted next?

## Defender Outputs

| Output | Use |
|---|---|
| Hashes | IOC tracking and enrichment |
| Strings | URLs, paths, registry keys, suspicious terms |
| Entropy and byte stats | Packed/encrypted region hints |
| PE/ELF/Mach-O metadata | Static triage and capability clues |
| JSON/CSV | Case notes and automation |
| YARA scan results | Detection seed validation |

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![LIEF](https://img.shields.io/badge/LIEF-Parser-orange.svg)](https://lief.quarkslab.com/)

A versatile Python tool to extract comprehensive metadata and characteristics from files. For **malware analysts**, **digital forensics**, and **SOC engineers**.

---

## 📖 Guide: how to use (with pictures)

**→ [One Tool to Rule Them All: File Metadata & Static Analysis for Malware Analysts and SOC Teams](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de)** (Medium article)

Step-by-step guide with screenshots: installation, `fileinfo.py` vs `Basic_inf_gathering.py`, hashes, strings, YARA, full static analysis, and MalwareBazaar workflow.

---

## Two interfaces

| Script | Use case |
|--------|----------|
| **`fileinfo.py`** | **Recommended.** Batch mode, JSON/CSV, PE/ELF/Mach-O, strings, optional YARA/ssdeep/tlsh. |
| **`Basic_inf_gathering.py`** | Single-file, human-readable table only (original behavior). |

---

## fileinfo.py — robust & powerful

### Features

- **Hashes**: MD5, SHA-1, SHA-256, SHA-384, SHA-512 (single pass); optional **ssdeep** and **tlsh** when installed.
- **Formats**: **PE** (Rich header, overlay, resources, signature, packing), **ELF** (entry, interpreter, sections/segments), **Mach-O** (entry, commands).
- **Magic numbers**: 60+ file types (executables, archives, documents, media).
- **Strings**: ASCII and UTF-16 LE extraction with configurable minimum length.
- **Output**: Human-readable table, **JSON**, or **CSV**; optional output file.
- **Batch**: Multiple files and/or **recursive directory** (`-r`).
- **Optional YARA**: Rule scanning when `yara-python` and a rules file are provided.
- **Full static analysis** (`--full`): Maximum metadata **without decompilation or code analysis**:
  - **Byte-level**: null ratio, printable ratio, byte frequency, longest null run.
  - **Entropy map**: per-block entropy to find packed/encrypted regions.
  - **Head/tail hex dump**: first and last bytes for structure inspection.
  - **String patterns**: URLs, IPv4, emails, Windows/Unix paths, registry keys (from raw bytes).
  - **PE deep**: machine type, subsystem, DLL characteristics (ASLR, DEP, etc.), section table (name, size, entropy), full import/export lists, exphash, relocations, TLS callbacks, delay imports, Rich header, resource types, version info (FileVersion, CompanyName, etc.).
  - **ELF deep**: class, machine, sections/segments, dynamic (NEEDED, RPATH, RUNPATH), exported/imported symbols, notes.
  - **Mach-O deep**: CPU type, file type, dylibs, segments, UUID.
  - **Containers**: ZIP file listing (names, sizes); OLE stream listing (optional `olefile`).

### Installation

```bash
# From PyPI
pip install 1200km-fileinfo
fileinfo /path/to/file.exe --json

# From source
git clone https://github.com/anpa1200/Basic-File-Information-Gathering-Script.git
cd Basic-File-Information-Gathering-Script
# On Debian/Ubuntu, ensure venv support: sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
python3 -m pip install -r requirements.txt
# Optional: pip install ssdeep py-tlsh yara-python
# For real malware download + analysis: pip install requests pyzipper
```

### Troubleshooting installation

- **`ModuleNotFoundError: No module named 'lief'`** — Install dependencies inside the project directory with the venv **activated** (see below). Run the script with the same Python that has the packages (e.g. `python3 Basic_inf_gathering.py file.exe` after activating the venv).

- **`venv/bin/activate: No such file or directory`** or **`venv/bin/python3: No such file or directory`** — The venv was not fully created. On Debian/Ubuntu you need the `python3-venv` package:

  ```bash
  sudo apt update
  sudo apt install python3-venv
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate
  python3 -m pip install -r requirements.txt
  ```

  Then run scripts with `python3 fileinfo.py ...` or `python3 Basic_inf_gathering.py ...` while the venv is active.

- **`venv/bin/pip: cannot execute: required file not found`** — The virtual environment is broken (e.g. Python path changed). Recreate it from the **project root** (where `requirements.txt` lives), and install the `python3-venv` package if needed (see above). Then:

  ```bash
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate
  python3 -m pip install -r requirements.txt
  ```

- **No venv / prefer system install** — You can install dependencies for your user with the system Python (no venv):

  ```bash
  python3 -m pip install --user -r requirements.txt
  python3 fileinfo.py /path/to/file.exe
  ```

### Usage

```bash
# Single file (table)
python3 fileinfo.py /path/to/file.exe

# Multiple files
python3 fileinfo.py file1.exe file2.bin

# Recursive directory
python3 fileinfo.py -r /path/to/samples/

# JSON output
python3 fileinfo.py --json /path/to/file.exe

# CSV (for spreadsheets / automation)
python3 fileinfo.py --csv -r ./samples/ -o report.csv

# Extra hashes + strings
python3 fileinfo.py --hashes md5,sha1,sha256,sha512 --strings --min-str-len 8 file.exe

# YARA scan
python3 fileinfo.py --yara /path/to/rules.yar file.exe

# Skip specific binary analysis
python3 fileinfo.py --no-elf --no-macho /path/to/pe_only/

# Full static analysis (max metadata, no decompilation)
python3 fileinfo.py --full /path/to/sample.exe
python3 fileinfo.py --full --json sample.exe -o full_report.json
```

### Options

| Option | Description |
|--------|-------------|
| `paths` | One or more files or directories. |
| `-r`, `--recursive` | Recurse into directories. |
| `--json` | Output JSON. |
| `--csv` | Output CSV (one row per file). |
| `-o`, `--output` | Write output to file. |
| `--hashes` | Comma-separated: md5, sha1, sha256, sha384, sha512. |
| `--no-fuzzy` | Disable ssdeep/tlsh. |
| `--strings` | Extract ASCII + Unicode strings. |
| `--min-str-len` | Minimum string length (default 6). |
| `--no-pe` / `--no-elf` / `--no-macho` | Skip that format’s analysis. |
| `--yara` | Path to YARA rules file. |
| `--full` | Full static analysis: byte stats, entropy map, head/tail hex, string patterns (URLs, IPs, paths, registry), PE/ELF/Mach-O deep (sections, imports/exports, relocs, version info, etc.), ZIP/OLE listing. No decompilation. |
| `-v`, `--verbose` | Verbose errors to stderr. |

---

## Basic_inf_gathering.py — simple single-file

### Usage

```bash
python3 Basic_inf_gathering.py <path_to_file>
```

- Single file only.
- Output: detailed table to stdout (PE timestamp, imphash, hashes, entropy, permissions, magic, file type, digital signature, entry point, packer).

### Dependencies

- **Python** 3.7+
- **LIEF**: `pip install lief`
- **cryptography** (optional, for PE certificate details): `pip install cryptography`

---

## Examples (fileinfo.py)

```bash
# Table output for one PE
$ python3 fileinfo.py sample.exe

# JSON for automation
$ python3 fileinfo.py --json sample.exe -o report.json

# Batch CSV
$ python3 fileinfo.py --csv -r ./malware_samples/ -o summary.csv

# With strings and YARA
$ python3 fileinfo.py --strings --yara rules.yar sample.exe

# Maximum static info (no decompilation)
$ python3 fileinfo.py --full sample.exe
$ python3 fileinfo.py --full --json sample.exe -o full.json
```

---

## Testing with real malware (from the wild)

To run the tool on **real Windows PE malware** and compare with MalwareBazaar metadata:

1. **Get a free API key** from [abuse.ch Authentication](https://auth.abuse.ch/) (required for MalwareBazaar).
2. **Install deps**: `pip install requests pyzipper`
3. **Download a sample and run full analysis**:

```bash
export ABUSE_CH_AUTH_KEY='your-key-here'

# Download one recent sample (API picks from recent detections) and run --full analysis
python3 download_malware_sample.py

# Download by known SHA256 (e.g. from a public report)
python3 download_malware_sample.py 9FDEA40A9872A77335AE3B733A50F4D1E9F8EFF193AE84E36FB7E5802C481F72

# Download by tag (e.g. Emotet, TrickBot) then analyze
python3 download_malware_sample.py --tag Emotet --limit 1
```

Output (per sample) under `malware_samples/<sha256>/`:

- Extracted binary (or `sample.bin` if not zipped)
- **`our_analysis.json`** — full static report from `fileinfo.py --full --json`
- **`bazaar_info.json`** — MalwareBazaar metadata (signature, imphash, ssdeep, tags, etc.) for comparison

Compare hashes, imphash, file type, and PE/string findings between `our_analysis.json` and `bazaar_info.json` (and any public report you have for that hash).

---

## Project layout

- **`fileinfo.py`** — Main CLI: hashes, PE/ELF/Mach-O, strings, YARA, `--full` static.
- **`static_analysis.py`** — Deep static analysis module (byte stats, entropy map, PE/ELF/Mach-O deep, string patterns, ZIP/OLE). Used when `--full` is set.
- **`download_malware_sample.py`** — Download real Windows PE samples from MalwareBazaar (abuse.ch), run full analysis, save Bazaar metadata for comparison.
- **`Basic_inf_gathering.py`** — Legacy single-file table script.

## Requirements

- **Python** 3.8+ (for `fileinfo.py`), 3.7+ (for `Basic_inf_gathering.py`)
- **LIEF**: required for PE/ELF/Mach-O parsing
- **cryptography**: optional, for PE digital signature details
- **ssdeep** / **py-tlsh**: optional, for fuzzy hashing
- **yara-python**: optional, for YARA scanning
- **olefile**: optional, for OLE/compound document stream listing in `--full`

---

## Related repositories & articles

| Resource | Link |
|----------|------|
| **Basic-File-Information-Gathering-Script (this repo)** | [GitHub](https://github.com/anpa1200/Basic-File-Information-Gathering-Script) · [Medium: File Metadata & Static Analysis](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de) |
| **Static-malware-Analysis-Orchestrator** | [GitHub](https://github.com/anpa1200/Static-malware-Analysis-Orchestrator) — one-command pipeline (triage, strings, PE imports, unpack) · [Medium: Full workflow](https://medium.com/@1200km/basic-static-malware-analysis-from-triage-to-unpacking-explained-and-automated-9442ef3b11b8) |
| **String-Analyzer** | [GitHub](https://github.com/anpa1200/String-Analyzer-) · [Medium: String Analyzer Guide](https://medium.com/@1200km/a-practical-guide-to-string-analyzer-extract-and-analyze-strings-from-binaries-without-the-875dc74e4868) |
| **PE-Import-Analyzer** | [GitHub](https://github.com/anpa1200/PE-Import-Analyzer) · [Medium: PE Import Analyzer Guide](https://medium.com/@1200km/pe-import-analyzer-a-practical-guide-for-malware-analysts-and-reverse-engineers-29b8b98aeaf3) |
| **Unpacker** | [GitHub](https://github.com/anpa1200/Unpacker) · [Medium: Unpacker Guide](https://medium.com/@1200km/unpacker-a-practical-guide-to-modular-malware-packer-detection-and-unpacking-cf8ba924f25b) |
| **Author** | [Medium @1200km](https://medium.com/@1200km) |

---

## License

See [LICENSE](LICENSE) for details.

## 1200km Ecosystem

This project is part of the 1200km security research ecosystem. Use [AdversaryGraph](https://1200km.com/adversarygraph/) for CTI-to-detection workflows, ATT&CK/ATLAS mapping, actor relevance, IOC enrichment, and analyst-ready reporting.

- [AdversaryGraph project hub](https://1200km.com/adversarygraph/)
- [AdversaryGraph documentation](https://1200km.com/adversarygraph-docs/)
- [Live ATT&CK/ATLAS workspace](https://1200km.com/threat-matrix/)
- [1200km security research ecosystem](https://1200km.com/)

