"""
Week 4: Advanced PE Feature Extractor
Extracts all 77 features required by malware_brain.pkl from a real .exe file.
"""

import pefile
import math

# --- Known suspicious Windows API calls commonly abused by malware ---
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "CreateProcessA", "CreateProcessW", "WinExec",
    "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
    "IsDebuggerPresent", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "RegSetValueExA", "RegSetValueExW", "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
    "HttpSendRequestA", "CryptEncrypt", "CryptDecrypt", "AdjustTokenPrivileges",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "WriteFile", "DeleteFileA",
}

# --- Standard, expected section names in legitimate PE files ---
STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata",
    ".rsrc", ".tls", ".reloc", ".pdata", ".didat", ".sdata",
}


def safe(func, default=0):
    """Run an extraction function; return a default if the field is missing/unparseable."""
    try:
        val = func()
        return val if val is not None else default
    except Exception:
        return default


def extract_section_features(pe):
    """Compute min/max stats across all sections. Returns a dict of 15 features."""
    sections = pe.sections
    if not sections:
        return {
            "SectionsLength": 0, "SuspiciousNameSection": 0,
            "SectionMinEntropy": 0, "SectionMaxEntropy": 0,
            "SectionMinRawsize": 0, "SectionMaxRawsize": 0,
            "SectionMinVirtualsize": 0, "SectionMaxVirtualsize": 0,
            "SectionMaxPhysical": 0, "SectionMinPhysical": 0,
            "SectionMaxVirtual": 0, "SectionMinVirtual": 0,
            "SectionMaxPointerData": 0, "SectionMinPointerData": 0,
            "SectionMaxChar": 0, "SectionMainChar": 0,
        }

    entropies, raw_sizes, virt_sizes = [], [], []
    physical_addrs, virtual_addrs, pointer_data, char_flags = [], [], [], []
    suspicious_name_count = 0

    for section in sections:
        entropies.append(safe(lambda s=section: s.get_entropy(), 0.0))
        raw_sizes.append(section.SizeOfRawData)
        virt_sizes.append(section.Misc_VirtualSize)
        physical_addrs.append(section.Misc_PhysicalAddress)
        virtual_addrs.append(section.VirtualAddress)
        pointer_data.append(section.PointerToRawData)
        char_flags.append(section.Characteristics)

        name = section.Name.decode(errors="ignore").strip("\x00").strip()
        if name not in STANDARD_SECTION_NAMES:
            suspicious_name_count += 1

    return {
        "SectionsLength": len(sections),
        "SuspiciousNameSection": suspicious_name_count,
        "SectionMinEntropy": min(entropies),
        "SectionMaxEntropy": max(entropies),
        "SectionMinRawsize": min(raw_sizes),
        "SectionMaxRawsize": max(raw_sizes),
        "SectionMinVirtualsize": min(virt_sizes),
        "SectionMaxVirtualsize": max(virt_sizes),
        "SectionMaxPhysical": max(physical_addrs),
        "SectionMinPhysical": min(physical_addrs),
        "SectionMaxVirtual": max(virtual_addrs),
        "SectionMinVirtual": min(virtual_addrs),
        "SectionMaxPointerData": max(pointer_data),
        "SectionMinPointerData": min(pointer_data),
        "SectionMaxChar": max(char_flags),
        "SectionMainChar": min(char_flags),  # dataset's naming, not a typo we can fix
    }


def extract_import_export_features(pe):
    """Count imported DLLs/functions, exports, and suspicious API usage. Returns 4 features."""
    directory_entry_import = 0
    directory_entry_import_size = 0
    suspicious_import_count = 0

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        directory_entry_import = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            directory_entry_import_size += len(entry.imports)
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode(errors="ignore")
                    if fname in SUSPICIOUS_APIS:
                        suspicious_import_count += 1

    directory_entry_export = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        directory_entry_export = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

    return {
        "DirectoryEntryImport": directory_entry_import,
        "DirectoryEntryImportSize": directory_entry_import_size,
        "DirectoryEntryExport": directory_entry_export,
        "SuspiciousImportFunctions": suspicious_import_count,
    }


def extract_data_directory_sizes(pe):
    """Pull raw sizes from the 5 key entries in the Optional Header's Data Directory table."""
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    entry_map = {
        "ImageDirectoryEntryExport": "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "ImageDirectoryEntryImport": "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "ImageDirectoryEntryResource": "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "ImageDirectoryEntryException": "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
        "ImageDirectoryEntrySecurity": "IMAGE_DIRECTORY_ENTRY_SECURITY",
    }
    result = {}
    for feature_name, pefile_const_name in entry_map.items():
        idx = pefile.DIRECTORY_ENTRY[pefile_const_name]
        result[feature_name] = safe(lambda i=idx: dirs[i].Size, 0)
    return result


def extract_features(filepath):
    """
    Main entry point. Returns a dict with all 77 feature values,
    ready to be reindexed against models/features.pkl before prediction.
    """
    pe = pefile.PE(filepath, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    features = {}

    # --- DOS Header (16 fields) ---
    dos = pe.DOS_HEADER
    dos_fields = [
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc",
        "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc",
        "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew",
    ]
    for f in dos_fields:
        features[f] = safe(lambda f=f: getattr(dos, f), 0)

    # --- COFF File Header (7 fields) ---
    fh = pe.FILE_HEADER
    file_header_fields = [
        "Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable",
        "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics",
    ]
    for f in file_header_fields:
        features[f] = safe(lambda f=f: getattr(fh, f), 0)

    # --- Optional Header (28 fields) ---
    oh = pe.OPTIONAL_HEADER
    optional_header_fields = [
        "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint",
        "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment",
        "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion",
        "MinorSubsystemVersion", "SizeOfHeaders", "CheckSum", "SizeOfImage",
        "Subsystem", "DllCharacteristics", "SizeOfStackReserve",
        "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit",
        "LoaderFlags", "NumberOfRvaAndSizes",
    ]
    for f in optional_header_fields:
        features[f] = safe(lambda f=f: getattr(oh, f), 0)

    # --- Derived section-entropy features (16 fields) ---
    features.update(extract_section_features(pe))

    # --- Import/export counts (4 fields) ---
    features.update(extract_import_export_features(pe))

    # --- Data directory sizes (5 fields) ---
    features.update(extract_data_directory_sizes(pe))

    pe.close()
    return features


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "data/calc.exe"
    result = extract_features(target)
    print(json.dumps(result, indent=2))
    print(f"\nTotal features extracted: {len(result)}")