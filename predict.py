"""
Week 4: Predict using the Advanced Extractor.
"""

import joblib
import pandas as pd
from src.extractor import extract_features

MODEL_PATH = "models/malware_brain.pkl"
FEATURES_PATH = "models/features.pkl"


def predict(filepath):
    model = joblib.load(MODEL_PATH)
    required_features = joblib.load(FEATURES_PATH)

    raw_features = extract_features(filepath)

    # Build a single-row DataFrame, then force it into the EXACT column
    # order the model was trained on. Any feature our extractor missed
    # gets zero-filled here — but now that should be 0 features, not 58.
    df = pd.DataFrame([raw_features])
    df = df.reindex(columns=required_features, fill_value=0)

    missing = set(required_features) - set(raw_features.keys())
    if missing:
        print(f"WARNING: {len(missing)} features zero-filled: {missing}")
    else:
        print("All 77 features extracted successfully — no zero-fill.")

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]
    confidence = max(probability) * 100

    label = "MALICIOUS" if prediction == 1 else "BENIGN"
    print(f"\nFile: {filepath}")
    print(f"Verdict: {label}")
    print(f"Confidence: {confidence:.2f}%")

    return label, confidence


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "data/calc.exe"
    predict(target)