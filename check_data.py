import pandas as pd
import os

filepath = 'data/data1.csv'

if not os.path.exists(filepath):
    print(f"[!] Error: Cannot find {filepath}. Did you put it in the 'data' folder?")
else:
    try:
        df = pd.read_csv(filepath)
        print("--- DATASET VERIFIED ---")
        print(f"Total Samples (Rows): {df.shape[0]}")
        print(f"Total Features (Columns): {df.shape[1]}")
        
        if 'Malware' in df.columns:
            malicious = df[df['Malware'] == 1].shape[0]
            benign = df[df['Malware'] == 0].shape[0]
            print(f"Malicious files: {malicious}")
            print(f"Benign files: {benign}")
        else:
            print("[!] Target column 'Malware' not found.")
    except Exception as e:
        print(f"[!] Error reading file: {e}")