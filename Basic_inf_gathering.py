import hashlib
import os
import argparse
import math
import stat
import shutil
import json
import subprocess
import time
import datetime
import lief  # Library for parsing executables

# Disable LIEF logging to suppress warnings
lief.logging.disable()

def calculate_hash(file_path, hash_func):
    """Calculate file hash using the specified hash function."""
    hash_obj = hash_func()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def calculate_entropy(file_path):
    """Calculate Shannon entropy of a file to detect packing or encryption."""
    with open(file_path, "rb") as f:
        byte_arr = f.read()
    if not byte_arr:
        return 0.0
    byte_counts = {byte: 0 for byte in range(256)}
    for byte in byte_arr:
        byte_counts[byte] += 1
    file_size = len(byte_arr)
    entropy = -sum((count / file_size) * math.log2(count / file_size)
                   for count in byte_counts.values() if count > 0)
    return entropy

def get_file_permissions(file_path):
    """Retrieve file permissions in human-readable format."""
    mode = os.stat(file_path).st_mode
    return stat.filemode(mode)

def get_pe_timestamp(file_path):
    """Extract compilation timestamp from PE headers."""
    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Not a PE file"
        timestamp = binary.header.time_date_stamps
        if timestamp == 0:
            return "No timestamp found"
        # Use timezone-aware UTC datetime.
        compiled_time = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        current_time = datetime.datetime.now(datetime.timezone.utc)
        status = "⚠️ Possibly Faked" if compiled_time.year < 1980 or compiled_time.year > current_time.year else "✅ Legit"
        return f"{compiled_time.strftime('%Y-%m-%d %H:%M:%S')} ({status})"
    except Exception as e:
        return f"Error extracting timestamp: {str(e)}"

def detect_compiler_and_language(file_path):
    """Detect compiler, linker, and programming language used in an executable."""
    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Unknown"
        compiler_info = "Unknown"
        programming_lang = "Unknown"
        imported_funcs = [func.name.lower() for func in binary.imports] if binary.imports else []
        section_names = [section.name.lower() for section in binary.sections] if binary.sections else []
        if "msvcrt.dll" in imported_funcs:
            compiler_info = "MSVC (Microsoft Visual C++)"
        elif "libgcc_s_dw2-1.dll" in imported_funcs or ".gcc_except_table" in section_names:
            compiler_info = "GCC (MinGW or Cygwin)"
        elif "libc.so.6" in imported_funcs:
            compiler_info = "GCC (Linux)"
        elif ".go.buildid" in section_names:
            compiler_info = "Go Compiler"
            programming_lang = "Go"
        elif ".rustc" in section_names:
            compiler_info = "Rust Compiler"
            programming_lang = "Rust"
        elif ".data" in section_names and ".rdata" in section_names and "ntdll.dll" in imported_funcs:
            compiler_info = "Delphi Compiler"
            programming_lang = "Delphi/Pascal"
        elif ".idata" in section_names and "python3.dll" in imported_funcs:
            compiler_info = "Embedded Python"
            programming_lang = "Python"
        elif ".data" in section_names and "libobjc.A.dylib" in imported_funcs:
            compiler_info = "Objective-C Runtime"
            programming_lang = "Objective-C"
        return f"{compiler_info} (Language: {programming_lang})"
    except Exception as e:
        return f"Error detecting compiler: {str(e)}"

def get_magic_number(file_path, num_bytes=4):
    """Retrieve the magic number (first few bytes) of a file in hex format."""
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(num_bytes)
        return magic_bytes.hex().upper()
    except Exception as e:
        return f"Error reading magic number: {str(e)}"

def check_filetype_from_magic(file_path):
    """
    Check file type based on the magic number using a dictionary of common signatures.
    The dictionary now includes at least 50 common magic numbers.
    """
    magic_signatures = {
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
        "3C3F786D6C": "XML document",
        "464F524D": "AIFF audio file",
        "4F676753": "OGG audio file",
        "FFD8FF": "JPEG image",
        "7B5C727466": "Rich Text Format (RTF)",
        "EFBBBF": "UTF-8 encoded text file (BOM present)",
        "FFFE": "UTF-16 encoded text file (BOM present)",
        "4C000000": "Windows Shortcut (LNK file)",
        "504B030414000600": "Office Open XML document",
        "2E524D46": "RealMedia file",
        "1F9D": "Unix compress (.Z) file",
        "252150532D41646F6265": "PostScript document",
        "000001BA": "MPEG program stream",
        "000001B3": "MPEG video file",
        "3C68746D6C": "HTML document",
        "3C21444F": "HTML document",
        "464C56": "FLV video file",
        "1A45DFA3": "Matroska (MKV) video file",
        "0A": "PCX image file",
        "425A68": "BZip2 archive",
        "D4C3B2A1": "PCAP capture file",
        "4D5A9000": "Windows Executable (Extended signature)",
        "474946383961": "GIF87a image",
        "474946383761": "GIF89a image"
    }
    try:
        with open(file_path, "rb") as f:
            header_bytes = f.read(32)
        header_hex = header_bytes.hex().upper()
    except Exception as e:
        return f"Error reading file header: {str(e)}"
    for sig, ftype in sorted(magic_signatures.items(), key=lambda x: len(x[0]), reverse=True):
        if header_hex.startswith(sig):
            return ftype
    return "Unknown file type from magic number"

def check_digital_signature(file_path):
    """
    Check if the file is digitally signed. If it is a PE file with a digital signature,
    parse the embedded certificates using the cryptography library and return details.
    Only the organization names from the subject and issuer are extracted.
    """
    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Not a PE file; digital signature analysis not applicable."
    except Exception as e:
        return f"Error parsing file for digital signature: {str(e)}"
    
    if not binary.has_signatures:
        return "File is not digitally signed."
    
    # Access the first signature for analysis.
    signature = binary.signatures[0]
    result = ""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID
        # Use timezone-aware UTC datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        for idx, cert in enumerate(signature.certificates):
            try:
                if hasattr(cert, "raw"):
                    cert_der = cert.raw() if callable(cert.raw) else cert.raw
                elif hasattr(cert, "data"):
                    cert_der = cert.data
                elif hasattr(cert, "content"):
                    cert_der = cert.content
                else:
                    raise Exception("Certificate data not available")
                cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                # Extract organization names
                subject_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                issuer_attrs = cert_obj.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                subject_org = subject_attrs[0].value if subject_attrs else "N/A"
                issuer_org = issuer_attrs[0].value if issuer_attrs else "N/A"
                serial = cert_obj.serial_number
                not_before = cert_obj.not_valid_before_utc
                not_after = cert_obj.not_valid_after_utc
                valid = "Valid" if (not_before <= now <= not_after) else "Expired or not yet valid"
                self_signed = "Yes" if subject_org == issuer_org else "No"
                result += f"Certificate {idx+1}:\n"
                result += f"  Subject Organization : {subject_org}\n"
                result += f"  Issuer Organization  : {issuer_org}\n"
                result += f"  Serial Number        : {serial}\n"
                result += f"  Validity             : {not_before} to {not_after} ({valid})\n"
                result += f"  Self-signed          : {self_signed}\n"
            except Exception as ce:
                result += f"Certificate {idx+1}: Error parsing certificate: {str(ce)}\n"
    except ImportError:
        result = "cryptography module not installed, cannot parse certificate details."
    return result

def calculate_imphash(file_path):
    """
    Calculate the Import Hash (imphash) for a PE file.
    The imphash is computed by concatenating each imported DLL name and function name
    (in the order they appear) and then taking the MD5 hash of the resulting string.
    """
    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Not a PE file"
        import_entries = []
        # Loop through each import (each represents a DLL)
        for imp in binary.imports:
            dll_name = imp.name.lower() if imp.name else ""
            # Each DLL can have multiple function entries
            for entry in imp.entries:
                # Use function name if available; otherwise, use the ordinal
                func_name = entry.name.lower() if entry.name else f"ord_{entry.ordinal}"
                import_entries.append(f"{dll_name}.{func_name}")
        # Create the canonical string by joining entries with commas
        imphash_str = ",".join(import_entries)
        return hashlib.md5(imphash_str.encode("utf-8")).hexdigest()
    except Exception as e:
        return f"Error calculating imphash: {str(e)}"

def get_pe_header_offset(file_path):
    """
    Retrieve the offset of the PE header.
    The DOS header of a PE file contains a 4-byte field at offset 0x3C 
    that points to the PE header.
    """
    try:
        with open(file_path, "rb") as f:
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
        if len(pe_offset_bytes) < 4:
            return "Unable to read PE header offset"
        return int.from_bytes(pe_offset_bytes, byteorder="little")
    except Exception as e:
        return f"Error reading PE header offset: {str(e)}"
        
def get_entry_point(file_path):
    """
    Retrieve the entry point of the PE file (RVA and VA).
    """
    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Not a PE file"
        rva = binary.optional_header.addressof_entrypoint
        image_base = binary.optional_header.imagebase
        va = image_base + rva
        return f"RVA: 0x{rva:X}, VA: 0x{va:X}"
    except Exception as e:
        return f"Error retrieving entry point: {str(e)}"
        
def detect_packing(file_path):
    """Advanced pure-Python packer detection using multiple heuristics."""
    def section_entropy(sec):
        data = bytes(sec.content)
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        size = len(data)
        return -sum((c/size) * math.log2(c/size) for c in counts if c)

    try:
        binary = lief.parse(file_path)
        if not binary or not isinstance(binary, lief.PE.Binary):
            return "Unknown"
        secs = binary.sections or []
        entropies = []
        flags = []
        high_thresh = 7.2
        low_thresh = 3.0
        patterns = [
            "upx", "petite", "aspack", "fsg", "cryp", "packed",
            "stub", "themida", "scylla", "kkrunchy"
        ]
        for sec in secs:
            name = sec.name.strip("\x00").lower()
            ent = section_entropy(sec)
            entropies.append(ent)
            if ent >= high_thresh:
                flags.append(f"{sec.name}(ent>={high_thresh})")
            if ent <= low_thresh and sec.size < 0x200:
                flags.append(f"{sec.name}(ent<={low_thresh},size<{sec.size})")
            for pat in patterns:
                if pat in name:
                    flags.append(f"{sec.name}(name~{pat})")
        avg_ent = sum(entropies) / len(entropies) if entropies else 0
        max_ent = max(entropies) if entropies else 0
        if flags or avg_ent > 6.5:
            parts = []
            if flags:
                parts.append("flags=" + ",".join(sorted(set(flags))))
            if avg_ent > 6.5:
                parts.append(f"avg={avg_ent:.2f}")
            if max_ent > high_thresh:
                parts.append(f"max={max_ent:.2f}")
            return "Likely packed -> " + "; ".join(parts)
        return "Unpacked"
    except Exception as e:
        return f"Error detecting packing: {e}"
        
def print_beautiful(info):
    """
    Print the file information in a neatly formatted table.
    The 'Digital Signature' field is printed with its internal newlines preserved.
    """
    max_key_len = max(len(str(k)) for k in info.keys())
    border = "=" * 100  # Fixed width for simplicity
    header = " FILE INFORMATION "
    print(border)
    print(header.center(100))
    print(border)
    for key, value in info.items():
        if key == "Digital Signature":
            print(f"{key.ljust(max_key_len)} :")
            for line in value.splitlines():
                print(" " * (max_key_len + 3) + line.strip())
        else:
            val = str(value).replace("\n", " | ")
            print(f"{key.ljust(max_key_len)} : {val}")
    print(border)

def get_file_info(file_path):
    """
    Retrieve file details including imphash (displayed above other hashes), 
    hashes, size, entropy, permissions, PE timestamp, compiler info, magic number, 
    file type, digital signature & certificate analysis, and the PE header offset 
    in both decimal and hexadecimal formats.
    """
    if not os.path.isfile(file_path):
        print("Error: File not found!")
        return
    file_size = os.path.getsize(file_path)
    file_type = check_filetype_from_magic(file_path)
    entropy = calculate_entropy(file_path)
    permissions = get_file_permissions(file_path)
    pe_timestamp = get_pe_timestamp(file_path)
    compiler_info = detect_compiler_and_language(file_path)
    magic_number = get_magic_number(file_path)
    digital_signature_info = check_digital_signature(file_path)
    imphash_value = calculate_imphash(file_path)
    pe_header_offset = get_pe_header_offset(file_path)
    entry_point = get_entry_point(file_path)
    packing = detect_packing(file_path)
    # Format PE header offset in both decimal and hexadecimal
    if isinstance(pe_header_offset, int):
        pe_header_offset_str = f"{pe_header_offset} (0x{pe_header_offset:X})"
    else:
        pe_header_offset_str = pe_header_offset
    entropy_status = "⚠️ High (Possible Packing/Encryption)" if entropy > 7.5 else "✅ Normal"
    
    # Construct info dictionary with Import Hash above the file hashes
    info = {
        "File Name": os.path.basename(file_path),
        "File Path": os.path.abspath(file_path),
        "Import Hash": imphash_value,
        "MD5": calculate_hash(file_path, hashlib.md5),
        "SHA-1": calculate_hash(file_path, hashlib.sha1),
        "SHA-256": calculate_hash(file_path, hashlib.sha256),
        "File Size": f"{file_size} bytes ({file_size / (1024 * 1024):.2f} MB)",
        "Magic Number": magic_number,
        "File Type": file_type,
        "Entropy": f"{entropy:.2f} ({entropy_status})",
        "Permissions": permissions,
        "PE Timestamp": pe_timestamp,
        "Compiler & Language": compiler_info,
        "Digital Signature": digital_signature_info,
        "PE Header Offset": pe_header_offset_str,
        "Entry Point":  entry_point,
        "Packer": packing
    }
    print_beautiful(info)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract file details including imphash, hashes, size, entropy, PE timestamp, "
                    "compiler info, magic number, file type, digital signature & certificate analysis, "
                    "and the PE header offset in both decimal and hexadecimal."
    )
    parser.add_argument("file_path", help="Path to the file")
    args = parser.parse_args()
    get_file_info(args.file_path)
