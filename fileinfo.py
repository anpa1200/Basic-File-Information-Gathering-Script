#!/usr/bin/env python3
"""
Robust File Information & Metadata Gathering Tool
For malware analysis, forensics, and SOC. Supports PE, ELF, Mach-O; multiple output formats; batch mode.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import lief
    lief.logging.disable()
except ImportError:
    lief = None

import hashlib
import datetime


# ---------- Magic number database (extended) ----------
MAGIC_SIGNATURES = {
    "0000001866747970": "MP4 video file",
    "3026B2758E66CF11": "ASF/WMV video file",
    "CAFEBABE": "Java Class file",
    "D0CF11E0": "OLE Compound File (MS Office)",
    "1F8B08": "GZIP archive",
    "25504446": "PDF document",
    "424D": "BMP image",
    "4344303031": "ISO disk image",
    "465753": "SWF Flash file (uncompressed)",
    "47494638": "GIF image",
    "49492A00": "TIFF image (little-endian)",
    "494433": "MP3 audio (ID3)",
    "4D4D002A": "TIFF image (big-endian)",
    "4D546864": "MIDI file",
    "4D5A": "Windows Executable (MZ)",
    "504B0304": "ZIP archive",
    "52617221": "RAR archive",
    "377ABCAF271C": "7-Zip archive",
    "52494646": "RIFF file (AVI/WAV)",
    "7F454C46": "ELF executable",
    "89504E47": "PNG image",
    "38425053": "Photoshop Document (PSD)",
    "664C6143": "FLAC audio file",
    "435753": "SWF Flash file (compressed)",
    "FEEDFACE": "Mach-O executable (32-bit)",
    "FEEDFACF": "Mach-O executable (64-bit)",
    "FEEDFACB": "Mach-O executable (64-bit arm64)",
    "3C3F786D6C": "XML document",
    "464F524D": "AIFF audio file",
    "4F676753": "OGG audio file",
    "FFD8FF": "JPEG image",
    "7B5C727466": "Rich Text Format (RTF)",
    "EFBBBF": "UTF-8 text (BOM)",
    "FFFE": "UTF-16 LE text (BOM)",
    "4C000000": "Windows Shortcut (LNK)",
    "504B030414000600": "Office Open XML document",
    "2E524D46": "RealMedia file",
    "1F9D": "Unix compress (.Z)",
    "252150532D41646F6265": "PostScript document",
    "000001BA": "MPEG program stream",
    "000001B3": "MPEG video file",
    "3C68746D6C": "HTML document",
    "3C21444F": "HTML document",
    "464C56": "FLV video file",
    "1A45DFA3": "Matroska (MKV) video file",
    "425A68": "BZip2 archive",
    "D4C3B2A1": "PCAP capture file",
    "A1B2C3D4": "PCAP NG capture file",
    "4D5A9000": "Windows Executable (Extended MZ)",
    "474946383961": "GIF87a image",
    "474946383761": "GIF89a image",
    "53514C69746520666F726D6174203300": "SQLite database",
    "EDABEEDB": "RPM package",
    "1F8B": "GZIP (generic)",
    "FD377A585A00": "XZ archive",
    "286B333320": "LZ4 frame",
    "4B444D": "KDM volume",
    "7801730D626260": "Zstandard (zstd) frame",
}

# Optional fuzzy hashing
try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False
try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False

# Optional YARA
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# Deep static analysis (no decompilation)
try:
    from static_analysis import run_full_static
    HAS_FULL_STATIC = True
except ImportError:
    HAS_FULL_STATIC = False


def _read_chunked(path: str, chunk_size: int = 65536) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def calculate_hashes(file_path: str, algorithms: list[str]) -> dict[str, str]:
    """Compute multiple hashes in a single pass (4KB chunks)."""
    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    active = {a: algos[a]() for a in algorithms if a in algos}
    for chunk in _read_chunked(file_path, 4096):
        for h in active.values():
            h.update(chunk)
    return {a: active[a].hexdigest() for a in active}


def hash_ssdeep(file_path: str) -> str | None:
    if not HAS_SSDEEP:
        return None
    try:
        return ssdeep.hash_from_file(file_path)
    except Exception:
        return None


def hash_tlsh(file_path: str) -> str | None:
    if not HAS_TLSH:
        return None
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return tlsh.hash(data)
    except Exception:
        return None


def calculate_entropy(file_path: str) -> float:
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def entropy_severity(entropy: float) -> str:
    """Return human-readable severity for entropy (0–8 scale)."""
    if entropy >= 7.0:
        return "High (possible packing/encryption)"
    if entropy >= 6.5:
        return "Elevated"
    if entropy >= 4.5:
        return "Normal"
    return "Low"


def get_file_permissions(file_path: str) -> str:
    return stat.filemode(os.stat(file_path).st_mode)


def get_magic_and_type(file_path: str, num_bytes: int = 32) -> tuple[str, str]:
    try:
        with open(file_path, "rb") as f:
            header = f.read(num_bytes)
    except Exception:
        return "Error reading file", "Unknown"
    hex_header = header.hex().upper()
    magic_short = header[:4].hex().upper() if len(header) >= 4 else hex_header
    for sig, ftype in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if hex_header.startswith(sig):
            return magic_short, ftype
    return magic_short, "Unknown (from magic)"


def extract_strings(file_path: str, min_len: int = 6, ascii_only: bool = False) -> list[str]:
    """Extract ASCII and (optionally) UTF-16 LE strings."""
    with open(file_path, "rb") as f:
        data = f.read()
    result = []
    # ASCII
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in ascii_re.finditer(data):
        result.append(m.group().decode("ascii", errors="replace"))
    if ascii_only:
        return result
    # UTF-16 LE (common in PE)
    try:
        unicode_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
        for m in unicode_re.finditer(data):
            result.append(m.group().decode("utf-16-le", errors="replace"))
    except Exception:
        pass
    return result


# ---------- PE ----------
def _get_pe_binary(file_path: str) -> lief.PE.Binary | None:
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        return b if isinstance(b, lief.PE.Binary) else None
    except Exception:
        return None


def pe_timestamp(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A (not PE)"
    ts = b.header.time_date_stamps
    if ts == 0:
        return "No timestamp"
    try:
        t = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        status = "Possibly faked" if t.year < 1980 or t.year > now.year else "OK"
        return f"{t.strftime('%Y-%m-%d %H:%M:%S')} UTC ({status})"
    except Exception as e:
        return str(e)


def pe_compiler_language(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A"
    imports = [e.name.lower() for imp in (b.imports or []) for e in imp.entries if e.name]
    sections = [s.name.lower().strip("\x00") for s in (b.sections or [])]
    if any("msvcrt" in i or "msvcr" in i for i in imports):
        return "MSVC (C/C++)"
    if any("libgcc" in i or "libstdc" in i for i in imports) or ".gcc_except_table" in sections:
        return "GCC (MinGW/Cygwin)"
    if ".go.buildid" in sections:
        return "Go"
    if ".rustc" in sections:
        return "Rust"
    if "python" in " ".join(imports):
        return "Python (embedded)"
    if "delphi" in " ".join(sections) or "borland" in " ".join(sections):
        return "Delphi"
    return "Unknown"


def pe_imphash(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b or not b.imports:
        return "N/A (not PE or no imports)"
    parts = []
    for imp in b.imports:
        dll = (imp.name or "").lower()
        for e in imp.entries:
            name = (e.name or f"ord_{e.ordinal}").lower()
            parts.append(f"{dll}.{name}")
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def pe_header_offset(file_path: str) -> str:
    try:
        with open(file_path, "rb") as f:
            f.seek(0x3C)
            raw = f.read(4)
        if len(raw) < 4:
            return "N/A"
        off = int.from_bytes(raw, "little")
        return f"{off} (0x{off:X})"
    except Exception:
        return "N/A"


def pe_entry_point(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A"
    try:
        rva = b.optional_header.addressof_entrypoint
        base = b.optional_header.imagebase
        return f"RVA 0x{rva:X}, VA 0x{base + rva:X}"
    except Exception:
        return "N/A"


def pe_rich_header(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b or not hasattr(b, "rich_header") or not b.rich_header:
        return "N/A"
    try:
        entries = getattr(b.rich_header, "entries", []) or []
        if not entries:
            return "Present (no parse)"
        parts = [f"{e.id}:{e.build_id}" for e in entries[:5]]
        return ", ".join(parts) + (" ..." if len(entries) > 5 else "")
    except Exception:
        return "Present (parse error)"


def pe_resources_summary(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b or not hasattr(b, "resources") or not b.resources:
        return "None"
    try:
        # LIEF resources tree: count types
        def count_nodes(node):
            n = 1
            if hasattr(node, "childs"):
                for c in node.childs:
                    n += count_nodes(c)
            return n
        return str(count_nodes(b.resources)) + " resource nodes"
    except Exception:
        return "Present"


def pe_overlay(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A"
    try:
        last_end = 0
        for s in b.sections or []:
            end = s.offset + s.size
            if end > last_end:
                last_end = end
        file_size = os.path.getsize(file_path)
        overlay = file_size - last_end
        if overlay <= 0:
            return "None"
        return f"{overlay} bytes (0x{overlay:X})"
    except Exception:
        return "N/A"


def pe_digital_signature(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A"
    if not getattr(b, "has_signatures", False) or not b.signatures:
        return "Not signed"
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID
        sig = b.signatures[0]
        certs = getattr(sig, "certificates", []) or []
        lines = []
        for i, cert in enumerate(certs[:3]):
            try:
                raw = cert.raw() if callable(getattr(cert, "raw", None)) else getattr(cert, "raw", None) or cert.data
                c = x509.load_der_x509_certificate(raw, default_backend())
                subj = c.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                iss = c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                subj_o = subj[0].value if subj else "N/A"
                iss_o = iss[0].value if iss else "N/A"
                lines.append(f"  Cert {i+1}: Subject={subj_o}, Issuer={iss_o}")
            except Exception:
                lines.append(f"  Cert {i+1}: (parse error)")
        return "\n".join(lines) if lines else "Signed (no cert parse)"
    except ImportError:
        return "Signed (install cryptography for details)"


def pe_packing(file_path: str) -> str:
    b = _get_pe_binary(file_path)
    if not b:
        return "N/A"
    try:
        def sec_entropy(sec):
            d = bytes(sec.content) if sec.content else b""
            if not d:
                return 0.0
            c = [0] * 256
            for x in d:
                c[x] += 1
            n = len(d)
            return -sum((x / n) * math.log2(x / n) for x in c if x)
        entropies = [sec_entropy(s) for s in (b.sections or [])]
        if not entropies:
            return "Unknown"
        avg = sum(entropies) / len(entropies)
        high = 7.2
        names = "".join((s.name or "").lower() for s in b.sections or [])
        packed_names = ["upx", "petite", "aspack", "themida", "packed", "cryp", "fsg"]
        if any(p in names for p in packed_names) or avg > 6.8:
            return f"Likely packed (avg_ent={avg:.2f})"
        return "Unpacked"
    except Exception as e:
        return str(e)


# ---------- ELF ----------
def _get_elf_binary(file_path: str):
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        return b if isinstance(b, lief.ELF.Binary) else None
    except Exception:
        return None


def elf_info(file_path: str) -> dict[str, Any]:
    b = _get_elf_binary(file_path)
    if not b:
        return {}
    out = {}
    try:
        out["entry"] = f"0x{b.header.entrypoint:X}" if b.header.entrypoint else "N/A"
    except Exception:
        out["entry"] = "N/A"
    try:
        interp = b.get_interpreter()
        out["interpreter"] = interp if interp else "None"
    except Exception:
        out["interpreter"] = "N/A"
    try:
        secs = b.sections or []
        out["sections"] = len(secs)
        out["segments"] = len(b.segments or [])
    except Exception:
        out["sections"] = out["segments"] = "N/A"
    return out


# ---------- Mach-O ----------
def _get_macho_binary(file_path: str):
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        return b if isinstance(b, lief.MachO.Binary) else None
    except Exception:
        return None


def macho_info(file_path: str) -> dict[str, Any]:
    b = _get_macho_binary(file_path)
    if not b:
        return {}
    out = {}
    try:
        out["entry"] = f"0x{b.entrypoint:X}" if b.entrypoint else "N/A"
    except Exception:
        out["entry"] = "N/A"
    try:
        out["commands"] = len(b.commands) if b.commands else 0
    except Exception:
        out["commands"] = "N/A"
    return out


# ---------- YARA ----------
def yara_scan(file_path: str, rules_path: str | None) -> list[str]:
    if not HAS_YARA or not rules_path or not os.path.isfile(rules_path):
        return []
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        return [f"{m.rule}: {m.namespace}" for m in matches]
    except Exception:
        return []


def gather_file_info(
    file_path: str,
    *,
    hash_algos: list[str] | None = None,
    include_fuzzy: bool = True,
    include_strings: bool = False,
    min_str_len: int = 6,
    include_pe: bool = True,
    include_elf: bool = True,
    include_macho: bool = True,
    yara_rules: str | None = None,
    full_static: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    hash_algos = hash_algos or ["md5", "sha1", "sha256"]
    if not os.path.isfile(file_path):
        return {"error": "File not found", "path": file_path}
    st = os.stat(file_path)
    size = st.st_size
    magic_hex, file_type = get_magic_and_type(file_path)
    hashes = calculate_hashes(file_path, hash_algos)
    if include_fuzzy and HAS_SSDEEP:
        h = hash_ssdeep(file_path)
        if h:
            hashes["ssdeep"] = h
    if include_fuzzy and HAS_TLSH:
        h = hash_tlsh(file_path)
        if h:
            hashes["tlsh"] = h
    entropy = calculate_entropy(file_path)
    info = {
        "file_name": os.path.basename(file_path),
        "file_path": os.path.abspath(file_path),
        "file_size": size,
        "file_size_human": f"{size} bytes ({size / (1024*1024):.2f} MB)",
        "magic_number": magic_hex,
        "file_type": file_type,
        "entropy": round(entropy, 4),
        "entropy_note": entropy_severity(entropy),
        "permissions": get_file_permissions(file_path),
        "hashes": hashes,
    }
    # PE
    if include_pe and _get_pe_binary(file_path):
        info["pe"] = {
            "timestamp": pe_timestamp(file_path),
            "compiler": pe_compiler_language(file_path),
            "imphash": pe_imphash(file_path),
            "header_offset": pe_header_offset(file_path),
            "entry_point": pe_entry_point(file_path),
            "rich_header": pe_rich_header(file_path),
            "resources": pe_resources_summary(file_path),
            "overlay": pe_overlay(file_path),
            "signature": pe_digital_signature(file_path),
            "packing": pe_packing(file_path),
        }
    # ELF
    if include_elf and _get_elf_binary(file_path):
        info["elf"] = elf_info(file_path)
    # Mach-O
    if include_macho and _get_macho_binary(file_path):
        info["macho"] = macho_info(file_path)
    # Strings
    if include_strings:
        all_strings = extract_strings(file_path, min_len=min_str_len)
        info["strings_count"] = len(all_strings)
        info["strings_sample"] = all_strings[:200]
    # YARA
    if yara_rules:
        info["yara_matches"] = yara_scan(file_path, yara_rules)
    # Deep static analysis (no decompilation): byte stats, entropy map, PE/ELF/Mach-O deep, strings patterns, containers
    if full_static and HAS_FULL_STATIC:
        try:
            full = run_full_static(
                file_path,
                byte_stats_enable=True,
                entropy_blocks_enable=True,
                head_tail_enable=True,
                strings_patterns_enable=True,
                pe_deep_enable=include_pe,
                elf_deep_enable=include_elf,
                macho_deep_enable=include_macho,
                containers_enable=True,
            )
            info["static_analysis"] = full
        except Exception as e:
            info["static_analysis"] = {"error": str(e)}
    return info


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.2f} KB"
    return f"{n / (1024*1024):.2f} MB"


def _print_nested(d: dict[str, Any], indent: int = 2, max_list: int = 20) -> None:
    for k, v in d.items():
        pref = " " * indent
        if isinstance(v, dict):
            print(f"{pref}{k}:")
            _print_nested(v, indent + 2, max_list)
        elif isinstance(v, list):
            print(f"{pref}{k}: (list len={len(v)})")
            for i, item in enumerate(v[:max_list]):
                if isinstance(item, dict):
                    print(f"{pref}  [{i}]:")
                    _print_nested(item, indent + 4, 5)
                else:
                    print(f"{pref}  [{i}]: {item}")
            if len(v) > max_list:
                print(f"{pref}  ... and {len(v) - max_list} more")
        elif isinstance(v, str) and "\n" in v:
            print(f"{pref}{k}:")
            for line in v.splitlines()[:30]:
                print(f"{pref}  {line}")
        else:
            print(f"{pref}{k}: {v}")


def print_text_report(info: dict[str, Any], multiline_keys: set | None = None) -> None:
    multiline_keys = multiline_keys or {"pe", "signature", "yara_matches", "strings_sample"}
    border = "=" * 80
    print(border)
    print(" FILE INFORMATION ".center(80))
    print(border)
    for k, v in info.items():
        if k == "static_analysis":
            print("  static_analysis (deep, no decompilation):")
            if isinstance(v, dict) and "error" in v:
                print(f"    error: {v['error']}")
            elif isinstance(v, dict):
                _print_nested(v, indent=4, max_list=15)
            continue
        if k in ("hashes", "pe", "elf", "macho"):
            print(f"  {k}:")
            if isinstance(v, dict):
                for kk, vv in v.items():
                    print(f"    {kk}: {vv}")
            else:
                print(f"    {v}")
        elif k == "strings_sample":
            print(f"  strings_sample ({info.get('strings_count', 0)} total):")
            for s in (v or [])[:30]:
                print(f"    {repr(s)[:70]}")
            if len(v or []) > 30:
                print("    ...")
        elif k == "yara_matches" and v:
            print("  yara_matches:")
            for m in v:
                print(f"    {m}")
        elif isinstance(v, (list, tuple)) and k not in multiline_keys:
            print(f"  {k}: {v}")
        else:
            print(f"  {k}: {v}")
    print(border)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Robust file metadata & information gathering (PE/ELF/Mach-O, hashes, strings, YARA)."
    )
    ap.add_argument("paths", nargs="+", help="Files or directories to analyze")
    ap.add_argument("-r", "--recursive", action="store_true", help="Recurse into directories")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--csv", action="store_true", help="Output CSV (one row per file, key fields)")
    ap.add_argument("-o", "--output", type=str, help="Write output to file (default stdout)")
    ap.add_argument("--hashes", type=str, default="md5,sha1,sha256", help="Comma-separated: md5,sha1,sha256,sha384,sha512")
    ap.add_argument("--no-fuzzy", action="store_true", help="Disable ssdeep/tlsh if available")
    ap.add_argument("--strings", action="store_true", help="Extract strings (ASCII + Unicode)")
    ap.add_argument("--min-str-len", type=int, default=6, help="Minimum string length (default 6)")
    ap.add_argument("--no-pe", action="store_true", help="Skip PE-specific analysis")
    ap.add_argument("--no-elf", action="store_true", help="Skip ELF-specific analysis")
    ap.add_argument("--no-macho", action="store_true", help="Skip Mach-O-specific analysis")
    ap.add_argument("--yara", type=str, metavar="RULES_FILE", help="YARA rules file path")
    ap.add_argument("--full", action="store_true", help="Full static analysis: byte stats, entropy map, PE/ELF/Mach-O deep, string patterns, containers (no decompilation)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose errors")
    args = ap.parse_args()
    hash_algos = [a.strip().lower() for a in args.hashes.split(",") if a.strip()]
    files_to_scan = []
    for p in args.paths:
        path = Path(p)
        if not path.exists():
            if args.verbose:
                print(f"Skip (missing): {p}", file=sys.stderr)
            continue
        if path.is_file():
            files_to_scan.append(str(path))
        elif path.is_dir():
            if args.recursive:
                for f in path.rglob("*"):
                    if f.is_file():
                        files_to_scan.append(str(f))
            else:
                if args.verbose:
                    print(f"Skip (directory, use -r to recurse): {p}", file=sys.stderr)
    if not files_to_scan:
        print("No files to scan.", file=sys.stderr)
        sys.exit(1)
    results = []
    for fp in files_to_scan:
        try:
            info = gather_file_info(
                fp,
                hash_algos=hash_algos,
                include_fuzzy=not args.no_fuzzy,
                include_strings=args.strings,
                min_str_len=args.min_str_len,
                include_pe=not args.no_pe,
                include_elf=not args.no_elf,
                include_macho=not args.no_macho,
                yara_rules=args.yara,
                full_static=args.full,
                verbose=args.verbose,
            )
            results.append((fp, info))
        except Exception as e:
            results.append((fp, {"error": str(e), "path": fp}))
            if args.verbose:
                print(f"Error {fp}: {e}", file=sys.stderr)
    out_io = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        if args.csv:
            if not results:
                out_io.write("file_path,file_name,file_size,file_type,md5,sha256,entropy\n")
            else:
                writer = csv.writer(out_io)
                headers = ["file_path", "file_name", "file_size", "file_type", "entropy"]
                for a in hash_algos:
                    if a in (results[0][1].get("hashes") or {}):
                        headers.append(a)
                writer.writerow(headers)
                for fp, info in results:
                    if "error" in info:
                        row = [fp, "", "", "error", ""] + [""] * len(hash_algos)
                        writer.writerow(row)
                        continue
                    hashes = info.get("hashes") or {}
                    row = [
                        info.get("file_path", fp),
                        info.get("file_name", ""),
                        info.get("file_size", ""),
                        info.get("file_type", ""),
                        info.get("entropy", ""),
                    ]
                    for a in hash_algos:
                        row.append(hashes.get(a, ""))
                    writer.writerow(row)
        elif args.json:
            if len(results) == 1:
                json.dump(results[0][1], out_io, indent=2)
            else:
                json.dump([r[1] for _, r in results], out_io, indent=2)
            out_io.write("\n")
        else:
            for fp, info in results:
                if len(results) > 1:
                    print(f"\n--- {fp} ---\n")
                if "error" in info:
                    print(f"Error: {info['error']}")
                else:
                    print_text_report(info)
    finally:
        if args.output and out_io != sys.stdout:
            out_io.close()


if __name__ == "__main__":
    main()
