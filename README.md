# Basic-File-Information-Gathering-Script
This repository contains a versatile Python script, Basic_inf_gathering.py, designed to automate the extraction of critical metadata and characteristics from arbitrary files. It is particularly valuable for malware analysts, digital forensics investigators, and SOC engineers who need to rapidly triage files for suspicious or malicious behavior.


Table of Contents

Features

Installation

Usage

Function Reference

calculate_hash

calculate_entropy

get_file_permissions

get_pe_timestamp

detect_compiler_and_language

get_magic_number

check_filetype_from_magic

check_digital_signature

calculate_imphash

get_pe_header_offset

get_entry_point

detect_packing

print_beautiful

get_file_info

Examples

Dependencies

Contributing

License

Features

Hashes: MD5, SHA-1, SHA-256

Entropy Analysis: Shannon entropy to detect packing/encryption

File Permissions: Human-readable UNIX permissions

PE Metadata: Timestamp, compiler/linker, import hash, header offset, entry point

Magic Numbers: Identify file types from headers using common signatures (50+ types)

Digital Signatures: Extract and report certificate details (subject, issuer, validity)

Packer Detection: Heuristics on section entropy and names

Formatted Output: Neatly prints a table of all collected information

Installation

Download the script:

curl -O https://raw.githubusercontent.com/anpa1200/Malware_analysis/main/Basic_inf_gathering.py

Alternatively, download it via your browser from:
https://github.com/anpa1200/Malware_analysis/blob/main/Basic_inf_gathering.py

Create and activate a Python virtual environment (recommended):

python3 -m venv venv
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

If you plan to parse and validate digital signatures, ensure cryptography is installed:

pip install cryptography

Usage

python Basic_inf_gathering.py <path_to_file>

<path_to_file>: Path to the target file you wish to analyze.

The script will print a comprehensive report to STDOUT.

Function Reference

calculate_hash(file_path, hash_func)

Calculates the cryptographic hash of the file at file_path using the provided hashing constructor (e.g., hashlib.md5). Reads in chunks for memory efficiency.

calculate_entropy(file_path)

Computes the Shannon entropy of the file to identify potential packing or encryption (high entropy > 7.5).

get_file_permissions(file_path)

Retrieves UNIX-style permissions in a human-readable string (e.g., -rwxr-xr--).

get_pe_timestamp(file_path)

Parses the PE header (using LIEF) to extract the compilation timestamp. Flags suspicious dates outside a plausible range as possibly faked.

detect_compiler_and_language(file_path)

Identifies likely compiler/runtime by inspecting import tables and section names (e.g., MSVC, GCC, Go, Rust).

get_magic_number(file_path, num_bytes=4)

Reads the first num_bytes and returns their hex representation. Useful for quick fingerprinting.

check_filetype_from_magic(file_path)

Matches the file header against a dictionary of 50+ well-known magic signatures to infer file type (PDF, PNG, ZIP, PE, ELF, etc.).

check_digital_signature(file_path)

Uses LIEF to detect embedded PE signatures. Parses certificates (via cryptography) to report subject/issuer organizations, validity dates, and self-signed status.

calculate_imphash(file_path)

Computes the “Import Hash” (imphash) of a PE by concatenating imported DLLs and functions and hashing the string—common in malware triage.

get_pe_header_offset(file_path)

Reads the DOS header field at offset 0x3C to locate the PE header offset.

get_entry_point(file_path)

Extracts the RVA and VA of the executable entry point from the Optional Header.

detect_packing(file_path)

Applies multiple heuristics (section entropy, names, average entropy) to guess if a PE is packed.

print_beautiful(info)

Formats and prints the collected information dictionary as a clean table, preserving multiline fields.

get_file_info(file_path)

Orchestrates all above functions, creates a summary dictionary, and invokes print_beautiful.

Examples

$ python Basic_inf_gathering.py samples/malicious.exe
====================================================================================================
                                         FILE INFORMATION                                          
====================================================================================================
File Name           : malicious.exe                                                           
File Path           : /home/user/samples/malicious.exe                                         
Import Hash         : abcdef1234567890abcdef1234567890                                           
MD5                 : 0123456789abcdef0123456789abcdef                                           
SHA-1               : fedcba9876543210fedcba9876543210fedcba98                                   
SHA-256             : ...                                                                      
File Size           : 1.23 MB                                                                 
Magic Number        : 4D5A9000                                                              
File Type           : Windows Executable (Extended signature)                                 
Entropy             : 6.12 (✅ Normal)                                                       
Permissions         : -rwxr--r--                                                           
PE Timestamp        : 2020-05-10 12:34:56 (✅ Legit)                                      
Compiler & Language : MSVC (Microsoft Visual C++) (Language: )                               
Digital Signature   :                                                                 
    Certificate 1:                                                                  
      Subject Org.     : Example Corp                                                     
      Issuer Org.      : Example CA                                                       
      Validity         : 2020-01-01 to 2022-01-01 (Expired or not yet valid)                
      Self-signed      : No                                                               
PE Header Offset    : 128 (0x80)                                                           
Entry Point         : RVA: 0x1200, VA: 0x401200                                            
Packer              : Unpacked                                                            
====================================================================================================

Dependencies

Python 3.7+

LIEF for PE parsing

cryptography (optional, for detailed certificate parsing)

Install all via:

pip install lief cryptography

Contributing

Feel free to open issues or pull requests for additional file-type signatures, heuristics, or usability improvements.

License

This project is licensed under the MIT License. See LICENSE for details.

