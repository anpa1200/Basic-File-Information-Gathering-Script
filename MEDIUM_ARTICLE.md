# One Tool to Rule Them All: File Metadata & Static Analysis for Malware Analysts and SOC Teams

*Extract hashes, PE/ELF/Mach-O metadata, strings, YARA hits, and deep static analysis—without ever running the file.*

**Published (with pictures):** [Medium — One Tool to Rule Them All…](https://medium.com/@1200km/one-tool-to-rule-them-all-file-metadata-static-analysis-for-malware-analysts-and-soc-teams-c6dba1f5b7de)

---

Whether you’re triaging a suspicious attachment, building a file-intel pipeline, or comparing your analysis to threat feeds, you need **one place** to get hashes, format-specific metadata, and optional deep static analysis—**without** decompiling or executing code.

**[Basic File Information Gathering Script](https://github.com/anpa1200/Basic-File-Information-Gathering-Script)** is a Python CLI that does exactly that. It’s built for **malware analysts**, **digital forensics**, and **SOC engineers** who want fast, scriptable file intelligence in table, JSON, or CSV form.

---

## Table of contents

1. [Why another file-info tool?](#why-another-file-info-tool)
2. [Two interfaces, one codebase](#two-interfaces-one-codebase)
3. [fileinfo.py vs Basic_inf_gathering.py](#fileinfopy-vs-basic_inf_gatheringpy)
4. [Installation](#installation)
5. [Quick start](#quick-start)
6. [Hashes and fuzzy hashing](#hashes-and-fuzzy-hashing)
7. [Strings and YARA](#strings-and-yara)
8. [Full static analysis (--full)](#full-static-analysis-full-maximum-metadata-no-decompilation)
9. [Tuning format-specific analysis](#tuning-format-specific-analysis)
10. [Real malware: MalwareBazaar integration](#real-malware-malwarebazaar-integration)
11. [Options at a glance](#options-at-a-glance)
12. [Who is this for?](#who-is-this-for)
13. [Summary](#summary)

---

## Why another file-info tool?

`file` and `md5sum` tell you type and one hash. Full-blown sandboxes and disassemblers are heavy and often overkill for “what is this file?” and “how does it compare to VirusTotal/MalwareBazaar?”. This tool sits in the middle:

- **Single pass** for MD5, SHA-1, SHA-256, SHA-384, SHA-512 (and optional ssdeep/tlsh).
- **Format-aware**: PE (Windows), ELF (Linux), Mach-O (macOS) with meaningful fields—timestamps, imphash, entry point, packing heuristics, digital signatures, Rich header, overlay.
- **60+ magic numbers** so you get a real file type, not just “data”.
- **Strings** (ASCII + UTF-16 LE), optional **YARA** scanning, and a **full static analysis** mode that gives you byte stats, entropy maps, head/tail hex, and pattern extraction (URLs, IPs, paths, registry keys)—**no decompilation**.

You can run it on one file, a list of files, or recursively over a directory, and get human-readable tables, **JSON**, or **CSV** for automation.

---

## Two interfaces, one codebase

| Script | Best for |
|--------|----------|
| **`fileinfo.py`** | Daily use: batch, JSON/CSV, PE/ELF/Mach-O, strings, optional YARA/ssdeep/tlsh, and `--full` static analysis. |
| **`Basic_inf_gathering.py`** | Single file, pretty table only (original “classic” behavior). |

The rest of this article focuses on **`fileinfo.py`**.

---

## fileinfo.py vs Basic_inf_gathering.py

| Aspect | **Basic_inf_gathering.py** | **fileinfo.py** |
|--------|----------------------------|------------------|
| **Purpose** | Single-file, human-readable report only (original script). | Batch-capable, multi-format tool with many options. |
| **Input** | One file path: `python3 Basic_inf_gathering.py <file>` | One or more paths; can recurse: `-r` for directories. |
| **Output** | One formatted table to stdout. | Table, **JSON**, or **CSV**; optional `-o` file. |
| **Hashes** | MD5, SHA-1, SHA-256 (separate reads). | MD5, SHA-1, SHA-256 (and SHA-384, SHA-512) in **one pass**; optional **ssdeep** and **tlsh**. |
| **File types** | PE only (magic + PE-specific fields). | **PE, ELF, Mach-O**; 60+ magic types. |
| **PE fields** | Timestamp, compiler/language, imphash, header offset, entry point, digital signature (with cert details), packer. | Same idea + **Rich header**, **resources summary**, **overlay**; signature summary (cert details if `cryptography` present). |
| **ELF / Mach-O** | No. | Yes: entry, interpreter, sections/segments (ELF); entry, commands (Mach-O). |
| **Strings** | No. | Optional `--strings` (ASCII + UTF-16 LE), `--min-str-len`. |
| **YARA** | No. | Optional `--yara <rules.yar>`. |
| **Deep static** | No. | Optional `--full`: byte stats, entropy map, head/tail hex, URL/IP/path/registry patterns, PE/ELF/Mach-O deep (sections, imports/exports, version info, etc.), ZIP/OLE listing (no decompilation). |
| **LIEF** | Required (script fails if missing). | Optional: PE/ELF/Mach-O blocks are skipped if LIEF not installed. |
| **Code style** | No type hints; Python 3.7+. | Type hints, `from __future__ import annotations`; Python 3.8+. |

**When to use which**

- **Basic_inf_gathering.py** — Quick, single-file PE report to the terminal; minimal dependencies (LIEF, optional `cryptography`).
- **fileinfo.py** — Default choice for batch, automation, JSON/CSV, YARA, strings, full static analysis, and non-PE (ELF/Mach-O).

---

## Installation

```bash
git clone https://github.com/anpa1200/Basic-File-Information-Gathering-Script.git
cd Basic-File-Information-Gathering-Script
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Optional but recommended for malware work:**

```bash
pip install ssdeep py-tlsh yara-python
# For PE certificate details:
pip install cryptography
# For OLE/compound doc listing in --full:
pip install olefile
```

---

## Quick start

**Single file (human-readable table):**

```bash
python3 fileinfo.py /path/to/sample.exe
```

**Multiple files:**

```bash
python3 fileinfo.py file1.exe file2.bin
```

**Recursive directory (e.g. a drop folder):**

```bash
python3 fileinfo.py -r /path/to/samples/
```

**JSON for automation or SIEM:**

```bash
python3 fileinfo.py --json /path/to/file.exe -o report.json
```

**CSV for spreadsheets or bulk comparison:**

```bash
python3 fileinfo.py --csv -r ./malware_samples/ -o summary.csv
```

You immediately get: file name/path, size, magic-based file type, entropy, permissions, and for PE/ELF/Mach-O—timestamp, compiler/language hints, imphash (PE), entry point, Rich header (PE), resources, overlay, digital signature, and packing heuristic.

---

## Hashes and fuzzy hashing

Default hashes are MD5, SHA-1, and SHA-256 (single read pass). You can add SHA-384/SHA-512 and control which hashes are computed:

```bash
python3 fileinfo.py --hashes md5,sha1,sha256,sha512 /path/to/file
```

With `ssdeep` and `py-tlsh` installed, you also get **ssdeep** and **tlsh** hashes unless you pass `--no-fuzzy`. These are invaluable for clustering and “similar file” lookups (e.g. MalwareBazaar, VirusTotal).

---

## Strings and YARA

**Strings** (ASCII and UTF-16 LE) with configurable minimum length:

```bash
python3 fileinfo.py --strings --min-str-len 8 sample.exe
```

**YARA** (when `yara-python` and a rules file are available):

```bash
python3 fileinfo.py --yara /path/to/rules.yar sample.exe
```

Matches appear in the report so you can quickly see which rules fired.

---

## Full static analysis (`--full`): maximum metadata, no decompilation

The `--full` flag runs an extra layer of **static** analysis: no execution, no decompilation. It adds:

- **Byte-level stats**: null ratio, printable ratio, byte frequency, longest null run.
- **Entropy map**: per-block entropy so you can spot packed or encrypted regions.
- **Head/tail hex dump**: first and last bytes for structure inspection.
- **String patterns**: URLs, IPv4, emails, Windows/Unix paths, registry keys (from raw bytes, including UTF-16 LE).
- **PE deep**: machine type, subsystem, DLL characteristics (ASLR, DEP, etc.), section table (name, size, entropy), full import/export lists, exphash, relocations, TLS callbacks, delay imports, Rich header, resource types, version info (FileVersion, CompanyName, etc.).
- **ELF deep**: class, machine, sections/segments, dynamic (NEEDED, RPATH, RUNPATH), exported/imported symbols, notes.
- **Mach-O deep**: CPU type, file type, dylibs, segments, UUID.
- **Containers**: ZIP file listing (names, sizes); OLE stream listing (if `olefile` is installed).

Example:

```bash
python3 fileinfo.py --full sample.exe
python3 fileinfo.py --full --json sample.exe -o full_report.json
```

This is the mode you want when building a **reproducible static report** to compare with MalwareBazaar/VirusTotal or to feed into your own pipelines.

---

## Tuning format-specific analysis

If you only care about PE (e.g. Windows-only lab):

```bash
python3 fileinfo.py --no-elf --no-macho -r ./pe_samples/
```

Same idea for ELF-only or Mach-O-only environments.

---

## Real malware: MalwareBazaar integration

The repo includes **`download_malware_sample.py`** to pull real Windows PE samples from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch), run full static analysis, and save MalwareBazaar metadata for comparison.

1. Get a free API key from [abuse.ch Authentication](https://auth.abuse.ch/).
2. Install deps: `pip install requests pyzipper`
3. Set your key: `export ABUSE_CH_AUTH_KEY='your-key'`

Then:

```bash
# Download one recent sample and run --full analysis
python3 download_malware_sample.py

# By known SHA256 (e.g. from a report)
python3 download_malware_sample.py 9FDEA40A9872A77335AE3B733A50F4D1E9F8EFF193AE84E36FB7E5802C481F72

# By tag (e.g. Emotet, TrickBot)
python3 download_malware_sample.py --tag Emotet --limit 1
```

Per sample, you get a directory under `malware_samples/<sha256>/` with the binary, **`our_analysis.json`** (from `fileinfo.py --full --json`), and **`bazaar_info.json`** (MalwareBazaar metadata). You can diff hashes, imphash, file type, and PE/string findings against the feed and public reports.

---

## Options at a glance

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
| `--full` | Full static analysis (byte stats, entropy map, patterns, PE/ELF/Mach-O deep, containers). No decompilation. |
| `-v`, `--verbose` | Verbose errors to stderr. |

---

## Who is this for?

- **Malware analysts**: Quick triage (hashes, type, entropy, packing, imphash) and deep static reports for comparison with threat intel.
- **Digital forensics**: Consistent metadata (including timestamps and signatures) across many files; CSV/JSON for timelines and tooling.
- **SOC engineers**: Scriptable file intelligence (JSON/CSV), optional YARA, and hashes that plug into VirusTotal/MalwareBazaar/EDR.

---

## Summary

**Basic File Information Gathering Script** gives you:

- One CLI (`fileinfo.py`) for batch file metadata and optional deep static analysis.
- Single-pass multi-hash (MD5 through SHA-512) plus optional ssdeep/tlsh.
- PE/ELF/Mach-O–aware fields: timestamps, imphash, entry point, packing, signatures, and with `--full`: sections, imports/exports, version info, entropy map, and string patterns (URLs, IPs, paths, registry).
- Output as table, JSON, or CSV for automation and integration.
- Optional YARA and a MalwareBazaar downloader script for real-sample workflow.

All of this is **static only**—no execution, no decompilation—so you can run it safely in automation and air-gapped labs. If you’re building or tightening a file-intel or malware-triage pipeline, this tool is worth a slot in your toolkit.

---

*Repository: [github.com/anpa1200/Basic-File-Information-Gathering-Script](https://github.com/anpa1200/Basic-File-Information-Gathering-Script)*
