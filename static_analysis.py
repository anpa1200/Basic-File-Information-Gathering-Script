"""
Deep static file analysis — no decompilation or code execution.
Maximum metadata extraction from: PE, ELF, Mach-O, byte stats, strings/patterns, containers.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import os
import re
import struct
import zipfile
from typing import Any, Iterator

try:
    import lief
    lief.logging.disable()
except ImportError:
    lief = None

# Optional OLE (MS Office, compound docs)
try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False


# ---------- Generic: byte-level statistics ----------
def byte_stats(file_path: str, max_file_size: int = 50 * 1024 * 1024) -> dict[str, Any]:
    """Byte distribution, null ratio, printable ratio, longest null run."""
    size = os.path.getsize(file_path)
    if size == 0:
        return {"size": 0, "null_ratio": 0.0, "printable_ratio": 0.0, "longest_null_run": 0}
    with open(file_path, "rb") as f:
        data = f.read(min(size, max_file_size))
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    null_count = counts[0]
    printable = counts[0x20] + counts[0x0a] + counts[0x0d] + sum(counts[0x21:0x7f])
    # Longest run of null bytes
    run = 0
    max_run = 0
    for b in data:
        if b == 0:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    # Top 10 most frequent bytes (for non-null)
    freq = [(i, c) for i, c in enumerate(counts) if c > 0 and i != 0]
    freq.sort(key=lambda x: -x[1])
    top_bytes = [f"0x{i:02X}({c})" for i, c in freq[:10]]
    return {
        "size_analyzed": n,
        "null_ratio": round(null_count / n, 4),
        "printable_ratio": round(printable / n, 4),
        "longest_null_run": max_run,
        "top_byte_frequencies": top_bytes,
    }


def entropy_per_block(file_path: str, block_size: int = 65536, max_blocks: int = 256) -> dict[str, Any]:
    """Entropy per block to locate high-entropy (packed/encrypted) regions."""
    size = os.path.getsize(file_path)
    if size == 0:
        return {"block_size": block_size, "entropy_per_block": [], "high_entropy_blocks": []}
    entropies = []
    high_thresh = 7.5
    high_blocks = []
    with open(file_path, "rb") as f:
        block_idx = 0
        while block_idx < max_blocks:
            chunk = f.read(block_size)
            if not chunk:
                break
            counts = [0] * 256
            for b in chunk:
                counts[b] += 1
            n = len(chunk)
            ent = -sum((c / n) * math.log2(c / n) for c in counts if c)
            entropies.append(round(ent, 3))
            if ent >= high_thresh:
                high_blocks.append({"block": block_idx, "offset": block_idx * block_size, "entropy": round(ent, 3)})
            block_idx += 1
    return {
        "block_size": block_size,
        "num_blocks": len(entropies),
        "entropy_per_block": entropies[:64],  # cap for output
        "high_entropy_blocks": high_blocks[:20],
        "overall_avg_entropy": round(sum(entropies) / len(entropies), 3) if entropies else 0,
    }


def head_tail_hex(file_path: str, head_bytes: int = 256, tail_bytes: int = 128) -> dict[str, str]:
    """First and last N bytes as hex dump (for structure inspection)."""
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        head = f.read(head_bytes)
    with open(file_path, "rb") as f:
        if size > tail_bytes:
            f.seek(size - tail_bytes)
        tail = f.read(tail_bytes)
    def to_hex(b: bytes, per_line: int = 16) -> str:
        lines = []
        for i in range(0, len(b), per_line):
            chunk = b[i:i + per_line]
            hex_part = " ".join(f"{x:02X}" for x in chunk)
            ascii_part = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
            lines.append(f"{i:04X}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)
    return {"head_hex": to_hex(head), "tail_hex": to_hex(tail)}


# ---------- String pattern extraction (no code analysis) ----------
def _extract_strings_raw(data: bytes, min_len: int, encodings: list[tuple[str, re.Pattern]]) -> list[str]:
    out = []
    for _enc_name, pattern in encodings:
        for m in pattern.finditer(data):
            try:
                s = m.group().decode(_enc_name, errors="replace").strip()
                if len(s) >= min_len:
                    out.append(s)
            except Exception:
                pass
    return out


# URL, IPv4, email, Windows path, Unix path, registry key
PATTERN_URL = re.compile(rb"https?://[^\s\x00<>\"']+", re.I)
PATTERN_IPV4 = re.compile(rb"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b")
PATTERN_EMAIL = re.compile(rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PATTERN_WIN_PATH = re.compile(rb"[A-Za-z]:\\[^\s\x00]+")
PATTERN_UNIX_PATH = re.compile(rb"/[a-zA-Z0-9_/.-]{4,}")
PATTERN_REGISTRY = re.compile(rb"(?:HKEY_[\w]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\x00]+", re.I)


def extract_string_patterns(file_path: str, min_len: int = 4) -> dict[str, list[str]]:
    """Extract URLs, IPs, emails, paths, registry keys from raw bytes (ASCII + UTF-16 LE)."""
    with open(file_path, "rb") as f:
        data = f.read()
    patterns = [
        ("urls", PATTERN_URL, "ascii"),
        ("ipv4", PATTERN_IPV4, "ascii"),
        ("emails", PATTERN_EMAIL, "ascii"),
        ("win_paths", PATTERN_WIN_PATH, "ascii"),
        ("unix_paths", PATTERN_UNIX_PATH, "ascii"),
        ("registry", PATTERN_REGISTRY, "ascii"),
    ]
    result = {name: [] for name, _, _ in patterns}
    seen = {name: set() for name, _, _ in patterns}
    for name, pat, enc in patterns:
        for m in pat.finditer(data):
            try:
                s = m.group().decode(enc, errors="replace").strip()
                if len(s) >= min_len and s not in seen[name]:
                    seen[name].add(s)
                    result[name].append(s)
            except Exception:
                pass
    # UTF-16 LE
    try:
        u16 = data.decode("utf-16-le", errors="ignore")
        u16_b = u16.encode("latin-1")
        for name, pat, _ in patterns:
            for m in pat.finditer(u16_b):
                try:
                    s = m.group().decode("latin-1").strip()
                    if len(s) >= min_len and s not in seen[name]:
                        seen[name].add(s)
                        result[name].append(s)
                except Exception:
                    pass
    except Exception:
        pass
    # Cap each list for output
    for k in result:
        result[k] = result[k][:200]
    return result


# ---------- PE deep static ----------
PE_MACHINE = {
    0x14c: "i386",
    0x8664: "x64 (AMD64)",
    0x1c4: "ARM NT",
    0xaa64: "ARM64",
    0x1c0: "ARM",
    0xebc: "EFI byte code",
}

PE_SUBSYSTEM = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS2 CUI",
    7: "POSIX CUI",
    9: "Windows CE",
    10: "EFI",
    11: "EFI boot",
}

DLL_CHARACTERISTICS = {
    0x0020: "High entropy VA",
    0x0040: "Dynamic base (ASLR)",
    0x0080: "Force integrity",
    0x0100: "NX compatible",
    0x0200: "No SEH",
    0x0400: "Do not bind",
    0x0800: "WDM driver",
    0x1000: "Terminal server aware",
    0x2000: "Control flow guard",
    0x4000: "Microsoft signed",
    0x8000: "Store app",
}


def _section_entropy(sec) -> float:
    d = bytes(sec.content) if getattr(sec, "content", None) else b""
    if not d:
        return 0.0
    c = [0] * 256
    for x in d:
        c[x] += 1
    n = len(d)
    return -sum((x / n) * math.log2(x / n) for x in c if x)


def pe_deep_static(file_path: str) -> dict[str, Any] | None:
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        if not isinstance(b, lief.PE.Binary):
            return None
    except Exception:
        return None
    out = {}
    # Header
    h = b.header
    try:
        m = int(h.machine)
        out["machine"] = PE_MACHINE.get(m, f"0x{m:X}")
    except (TypeError, ValueError):
        out["machine"] = str(h.machine)
    out["number_of_sections"] = h.numberof_sections
    out["timestamp"] = h.time_date_stamps
    try:
        out["timestamp_utc"] = str(datetime.datetime.fromtimestamp(h.time_date_stamps, tz=datetime.timezone.utc)) if h.time_date_stamps else "N/A"
    except Exception:
        out["timestamp_utc"] = "N/A"
    # Optional header
    o = b.optional_header
    out["subsystem"] = PE_SUBSYSTEM.get(o.subsystem, str(o.subsystem))
    out["dll_characteristics"] = o.dll_characteristics
    dc = getattr(o, "dll_characteristics", 0) or 0
    out["dll_characteristics_list"] = [DLL_CHARACTERISTICS.get(k, f"0x{k:X}") for k in DLL_CHARACTERISTICS if (dc & k)]
    out["imagebase"] = hex(o.imagebase)
    out["entry_point_rva"] = hex(o.addressof_entrypoint)
    out["section_alignment"] = o.section_alignment
    out["file_alignment"] = o.file_alignment
    out["size_of_image"] = o.sizeof_image
    out["checksum"] = o.checksum
    # Data directories
    try:
        dd = []
        for i in range(0, min(16, len(o.data_directory))):
            d = o.data_directory[i]
            if d.rva and d.size:
                dd.append({"index": i, "rva": hex(d.rva), "size": d.size})
        out["data_directories_used"] = dd
    except Exception:
        out["data_directories_used"] = []
    # Sections
    sections = []
    for s in (b.sections or []):
        ent = _section_entropy(s)
        sections.append({
            "name": s.name.strip("\x00"),
            "virtual_size": s.virtual_size,
            "size": s.size,
            "offset": s.offset,
            "entropy": round(ent, 3),
            "characteristics": hex(s.characteristics) if hasattr(s, "characteristics") else "N/A",
        })
    out["sections"] = sections
    # Imports
    imports_list = []
    for imp in (b.imports or []):
        dll = imp.name or ""
        apis = [e.name or f"ord_{e.ordinal}" for e in imp.entries]
        imports_list.append({"dll": dll, "apis": apis[:50], "api_count": len(apis)})
    out["imports"] = imports_list
    # Exports
    try:
        if hasattr(b, "exported_functions") and b.exported_functions:
            out["exports"] = [f.name for f in b.exported_functions[:100]]
            out["export_count"] = len(b.exported_functions)
        elif hasattr(b, "get_export") and b.get_export():
            exp = b.get_export()
            out["exports"] = [e.name for e in (exp.entries or [])[:100]]
            out["export_count"] = len(exp.entries or [])
        else:
            out["exports"] = []
            out["export_count"] = 0
    except Exception:
        out["exports"] = []
        out["export_count"] = 0
    # Export hash (like imphash but for exports)
    if out.get("exports"):
        exp_str = ",".join(sorted(e.lower() for e in out["exports"]))
        out["exphash"] = hashlib.md5(exp_str.encode()).hexdigest()
    # Relocations
    try:
        relocs = b.relocations or []
        out["relocation_count"] = len(relocs)
        out["relocation_blocks"] = [{"rva": hex(r.virtual_address), "block_size": r.block_size} for r in relocs[:20]]
    except Exception:
        out["relocation_count"] = 0
        out["relocation_blocks"] = []
    # TLS callbacks
    try:
        if hasattr(b, "tls") and b.tls and hasattr(b.tls, "callback"):
            out["tls_callbacks"] = [hex(c) for c in b.tls.callback]
        else:
            out["tls_callbacks"] = []
    except Exception:
        out["tls_callbacks"] = []
    # Delay imports
    try:
        if hasattr(b, "delay_imports") and b.delay_imports:
            out["delay_imports"] = [d.name for d in b.delay_imports]
        else:
            out["delay_imports"] = []
    except Exception:
        out["delay_imports"] = []
    # Rich header
    try:
        if b.rich_header and getattr(b.rich_header, "entries", None):
            out["rich_header_entries"] = [{"id": e.id, "build_id": e.build_id} for e in b.rich_header.entries[:30]]
        else:
            out["rich_header_entries"] = []
    except Exception:
        out["rich_header_entries"] = []
    # Resources: types present
    try:
        if b.resources:
            types = set()
            def walk(node, depth=0):
                if hasattr(node, "id") and node.id:
                    if depth == 0:
                        types.add(f"type_{node.id}")
                if hasattr(node, "childs"):
                    for c in node.childs:
                        walk(c, depth + 1)
            walk(b.resources)
            out["resource_types"] = list(types)
        else:
            out["resource_types"] = []
    except Exception:
        out["resource_types"] = []
    # Version info from resources (LIEF may not expose; try minimal parse)
    out["version_info"] = _pe_version_info(file_path, b)
    return out


def _pe_version_info(file_path: str, binary) -> dict[str, str]:
    """Try to read PE version info (FileVersion, ProductVersion, etc.) from resources."""
    result = {}
    try:
        if not hasattr(binary, "resources") or not binary.resources:
            return result
        # LIEF resource tree: look for RT_VERSION (16) and parse VS_VERSIONINFO
        raw = _get_pe_version_resource_raw(file_path, binary)
        if raw:
            result = _parse_pe_version_blob(raw)
    except Exception:
        pass
    return result


def _get_pe_version_resource_raw(file_path: str, binary) -> bytes | None:
    """Get raw bytes of RT_VERSION resource if present."""
    try:
        rsrc_sec = None
        for s in (binary.sections or []):
            if ".rsrc" in (s.name or "").lower():
                rsrc_sec = s
                break
        if not rsrc_sec:
            return None
        with open(file_path, "rb") as f:
            f.seek(rsrc_sec.offset)
            data = f.read(rsrc_sec.size)
        # Simplified: look for "VS_VERSION_INFO" in Unicode (common at start of version block)
        idx = data.find(b"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00")
        if idx >= 0:
            return data[idx:idx + 512]
        return None
    except Exception:
        return None


def _parse_pe_version_blob(blob: bytes) -> dict[str, str]:
    """Minimal VS_VERSIONINFO / StringFileInfo parsing (no full structure walk)."""
    result = {}
    # Look for key strings followed by value in UTF-16 LE
    keys = [b"FileVersion\x00", b"ProductVersion\x00", b"CompanyName\x00", b"FileDescription\x00", b"InternalName\x00", b"OriginalFilename\x00", b"LegalCopyright\x00"]
    for key in keys:
        pos = blob.find(key)
        if pos >= 0:
            # Value often follows after padding; simplified: look for next null-terminated wide string
            start = pos + len(key)
            # Align to 32-bit
            start = (start + 3) & ~3
            if start + 4 <= len(blob):
                val_len = struct.unpack_from("<H", blob, start)[0]
                if 0 < val_len < 256:
                    val_start = start + 2
                    try:
                        val = blob[val_start:val_start + val_len * 2].decode("utf-16-le", errors="ignore").strip("\x00 ")
                        if val and val.isprintable():
                            result[key.decode("ascii").replace("\x00", "")] = val
                    except Exception:
                        pass
    return result


# ---------- ELF deep static ----------
def elf_deep_static(file_path: str) -> dict[str, Any] | None:
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        if not isinstance(b, lief.ELF.Binary):
            return None
    except Exception:
        return None
    out = {}
    h = b.header
    out["class"] = "ELF32" if h.identity_class == lief.ELF.ELF_CLASS.CLASS32 else "ELF64"
    out["data"] = "LE" if h.identity_data == lief.ELF.ELF_DATA.LSB else "BE"
    out["machine"] = str(h.machine) if hasattr(h.machine, "name") else str(h.machine)
    out["type"] = str(h.file_type) if hasattr(h.file_type, "name") else str(h.file_type)
    out["entry"] = hex(h.entrypoint) if h.entrypoint else "N/A"
    out["interpreter"] = b.get_interpreter() or "N/A"
    # Sections
    sections = []
    for s in (b.sections or []):
        name = s.name if s.name else "(anonymous)"
        sh_type = str(s.type) if hasattr(s.type, "name") else str(s.type)
        sections.append({
            "name": name,
            "type": sh_type,
            "virtual_address": hex(s.virtual_address) if s.virtual_address else "0",
            "offset": s.offset,
            "size": s.size,
            "flags": s.flags if hasattr(s, "flags") else 0,
        })
    out["sections"] = sections[:50]
    # Segments
    segs = []
    for sg in (b.segments or [])[:20]:
        segs.append({
            "type": str(sg.type) if hasattr(sg.type, "name") else str(sg.type),
            "offset": sg.file_offset,
            "vaddr": hex(sg.virtual_address) if sg.virtual_address else "0",
            "filesz": sg.physical_size,
            "memsz": sg.virtual_size,
            "flags": sg.flags if hasattr(sg, "flags") else 0,
        })
    out["segments"] = segs
    # Dynamic
    dynamic = []
    try:
        for d in (b.dynamic_entries or []):
            if hasattr(d, "tag") and hasattr(d, "value"):
                tag_str = str(d.tag) if hasattr(d.tag, "name") else str(d.tag)
                if "NEEDED" in tag_str or "RPATH" in tag_str or "RUNPATH" in tag_str or "FLAGS" in tag_str or "INIT" in tag_str or "FINI" in tag_str:
                    dynamic.append({"tag": tag_str, "value": str(d.value)})
            if hasattr(d, "name") and d.name:
                dynamic.append({"tag": "NEEDED", "value": d.name})
    except Exception:
        pass
    out["dynamic_entries"] = dynamic[:40]
    # Exported/imported symbols (dynamic symbols)
    try:
        if hasattr(b, "exported_functions"):
            out["exported_functions"] = [s.name for s in b.exported_functions[:100]]
        else:
            out["exported_functions"] = []
        if hasattr(b, "imported_functions"):
            out["imported_functions"] = [s.name for s in b.imported_functions[:100]]
        else:
            out["imported_functions"] = []
    except Exception:
        out["exported_functions"] = []
        out["imported_functions"] = []
    # Notes (e.g. build-id)
    try:
        if hasattr(b, "notes"):
            out["notes"] = [{"type": str(n.type), "name": getattr(n, "name", "")} for n in (b.notes or [])[:10]]
        else:
            out["notes"] = []
    except Exception:
        out["notes"] = []
    return out


# ---------- Mach-O deep static ----------
def macho_deep_static(file_path: str) -> dict[str, Any] | None:
    if not lief:
        return None
    try:
        b = lief.parse(file_path)
        if isinstance(b, lief.MachO.FatBinary):
            b = b.at(0) if b.size() else None
        if not b or not isinstance(b, lief.MachO.Binary):
            return None
    except Exception:
        return None
    out = {}
    out["header"] = {
        "magic": hex(b.header.magic) if hasattr(b.header, "magic") else "N/A",
        "cpu_type": str(b.header.cpu_type) if hasattr(b.header, "cpu_type") else "N/A",
        "cpu_subtype": str(b.header.cpu_subtype) if hasattr(b.header, "cpu_subtype") else "N/A",
        "file_type": str(b.header.file_type) if hasattr(b.header, "file_type") else "N/A",
        "nb_cmds": b.header.nb_cmds if hasattr(b.header, "nb_cmds") else 0,
    }
    out["entrypoint"] = hex(b.entrypoint) if b.entrypoint else "N/A"
    # Load commands / dylibs
    dylibs = []
    libs = []
    try:
        for cmd in (b.commands or []):
            if hasattr(cmd, "command_type"):
                ct = str(cmd.command_type)
                if "LOAD_DYLIB" in ct or "LOAD_WEAK_DYLIB" in ct:
                    name = getattr(cmd, "name", None) or getattr(cmd, "path", None)
                    if name:
                        dylibs.append(name)
                if "LOAD_DYLIB" in ct or "ID_DYLIB" in ct:
                    path = getattr(cmd, "name", None) or getattr(cmd, "path", None)
                    if path:
                        libs.append(path)
    except Exception:
        pass
    out["dylibs"] = dylibs[:80]
    out["dylib_count"] = len(dylibs)
    # Segments
    segs = []
    try:
        for sg in (b.segments or [])[:20]:
            segs.append({
                "name": sg.name if hasattr(sg, "name") else "N/A",
                "virtual_address": hex(sg.virtual_address) if getattr(sg, "virtual_address", None) else "N/A",
                "virtual_size": getattr(sg, "virtual_size", 0),
                "file_size": getattr(sg, "physical_size", 0),
            })
        out["segments"] = segs
    except Exception:
        out["segments"] = []
    # UUID
    try:
        for cmd in (b.commands or []):
            if hasattr(cmd, "command_type") and "UUID" in str(cmd.command_type):
                out["uuid"] = getattr(cmd, "uuid", "N/A")
                break
        else:
            out["uuid"] = "N/A"
    except Exception:
        out["uuid"] = "N/A"
    return out


# ---------- Containers (listing only, no decompression of code) ----------
def zip_static_list(file_path: str) -> dict[str, Any] | None:
    """List ZIP contents: names, sizes, compression method."""
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            infos = z.infolist()
            entries = []
            for i in infos[:500]:
                entries.append({
                    "name": i.filename,
                    "compress_size": i.compress_size,
                    "file_size": i.file_size,
                    "compress_type": i.compress_type,
                })
            return {"entry_count": len(infos), "entries": entries}
    except Exception:
        return None


def ole_streams_list(file_path: str) -> dict[str, Any] | None:
    """List OLE (compound document) stream names."""
    if not HAS_OLEFILE:
        return None
    try:
        ole = olefile.OleFileIO(file_path)
        streams = ole.listdir()
        ole.close()
        return {"streams": ["/".join(s) for s in streams], "count": len(streams)}
    except Exception:
        return None


# ---------- Run full static analysis ----------
def run_full_static(
    file_path: str,
    *,
    byte_stats_enable: bool = True,
    entropy_blocks_enable: bool = True,
    head_tail_enable: bool = True,
    strings_patterns_enable: bool = True,
    pe_deep_enable: bool = True,
    elf_deep_enable: bool = True,
    macho_deep_enable: bool = True,
    containers_enable: bool = True,
    max_file_for_blocks: int = 20 * 1024 * 1024,
) -> dict[str, Any]:
    """Run all applicable static analysis and return one merged dict."""
    result = {}
    size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
    if byte_stats_enable and size > 0:
        result["byte_stats"] = byte_stats(file_path)
    if entropy_blocks_enable and size > 0 and size <= max_file_for_blocks:
        result["entropy_blocks"] = entropy_per_block(file_path)
    if head_tail_enable and size > 0:
        result["head_tail"] = head_tail_hex(file_path)
    if strings_patterns_enable and size > 0 and size <= 50 * 1024 * 1024:
        result["string_patterns"] = extract_string_patterns(file_path)
    if pe_deep_enable:
        pe = pe_deep_static(file_path)
        if pe:
            result["pe_deep"] = pe
    if elf_deep_enable:
        elf = elf_deep_static(file_path)
        if elf:
            result["elf_deep"] = elf
    if macho_deep_enable:
        macho = macho_deep_static(file_path)
        if macho:
            result["macho_deep"] = macho
    if containers_enable and size > 0:
        z = zip_static_list(file_path)
        if z:
            result["zip_list"] = z
        o = ole_streams_list(file_path)
        if o:
            result["ole_streams"] = o
    return result
