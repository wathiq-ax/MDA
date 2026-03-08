import pefile
import os

def extract_basic_info(filepath):
    print(f"[*] Attempting to analyze: {filepath}")
    
    if not os.path.exists(filepath):
        print("[!] Error: File not found.")
        return

    try:
        # Load the executable into pefile
        pe = pefile.PE(filepath)
        
        print("\n--- PE HEADER INFO ---")
        print(f"Machine Type: {pe.FILE_HEADER.Machine}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"Time Date Stamp: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"Characteristics: {pe.FILE_HEADER.Characteristics}")
        
        print("\n--- OPTIONAL HEADER INFO ---")
        print(f"Magic: {pe.OPTIONAL_HEADER.Magic}")
        print(f"Size of Code: {pe.OPTIONAL_HEADER.SizeOfCode}")
        print(f"Address of Entry Point: {pe.OPTIONAL_HEADER.AddressOfEntryPoint}")
        
        print("\n[+] Extraction successful.")

    except pefile.PEFormatError:
        print("[!] Error: The file is not a valid PE (Windows Executable) file.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    # Test it on the calculator
    TARGET_FILE = "data/calc.exe"
    extract_basic_info(TARGET_FILE)