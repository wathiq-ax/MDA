import pefile
import joblib
import pandas as pd
import os
import warnings

# Suppress scikit-learn version warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning)

def scan_file(filepath):
    print(f"[*] Scanning: {filepath}")
    
    if not os.path.exists(filepath):
        print("[!] Error: File not found.")
        return

    try:
        # 1. Load the AI Brain and the required Feature List
        model = joblib.load('models/malware_brain.pkl')
        features_list = joblib.load('models/features.pkl')
        
        # 2. Extract the file's DNA
        pe = pefile.PE(filepath)
        
        # 3. Build an empty dictionary with all 77 features set to 0 initially
        pe_data = {feature: 0 for feature in features_list}
        
        # 4. Fill in the DNA we can easily extract from the headers
        try:
            pe_data['Machine'] = pe.FILE_HEADER.Machine
            pe_data['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            pe_data['Characteristics'] = pe.FILE_HEADER.Characteristics
            pe_data['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            pe_data['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            pe_data['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            pe_data['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            pe_data['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            pe_data['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pe_data['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            pe_data['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            pe_data['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            pe_data['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            pe_data['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            pe_data['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            pe_data['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            pe_data['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            pe_data['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            pe_data['SectionsNb'] = pe.FILE_HEADER.NumberOfSections
        except AttributeError:
            # If the file is missing a specific header, we just keep the default 0
            pass

        # 5. Format the DNA into a Pandas row (just like the Kaggle CSV)
        df = pd.DataFrame([pe_data], columns=features_list)
        
        # 6. Ask the AI Brain to predict
        prediction = model.predict(df)[0]
        confidence = model.predict_proba(df)[0]
        
        print("\n=================================")
        if prediction == 1:
            print(f" [!] THREAT DETECTED: MALWARE")
            print(f" Confidence: {confidence[1]*100:.2f}%")
        else:
            print(f" [✓] FILE IS SAFE: BENIGN")
            print(f" Confidence: {confidence[0]*100:.2f}%")
        print("=================================\n")

    except Exception as e:
        print(f"[!] Analysis failed: {e}")

if __name__ == "__main__":
    # Let's test the AI against the Windows Calculator
    scan_file("data/calc.exe")