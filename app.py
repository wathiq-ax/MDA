"""
Week 4: Streamlit Dashboard for the Malware Detection Agent.
Single-file scan + persistent scan history + full 77-feature report.
"""

import streamlit as st
import pandas as pd
import joblib
import tempfile
import os
from datetime import datetime
from src.extractor import extract_features

MODEL_PATH = "models/malware_brain.pkl"
FEATURES_PATH = "models/features.pkl"
HISTORY_PATH = "data/scan_history.csv"

st.set_page_config(page_title="Malware Detection Agent", page_icon="🛡️", layout="wide")


@st.cache_resource
def load_model_and_features():
    model = joblib.load(MODEL_PATH)
    required_features = joblib.load(FEATURES_PATH)
    return model, required_features


def load_history():
    if os.path.exists(HISTORY_PATH):
        return pd.read_csv(HISTORY_PATH)
    return pd.DataFrame(columns=["Timestamp", "Filename", "Verdict", "Confidence (%)"])


def save_to_history(filename, verdict, confidence):
    history = load_history()
    new_row = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Filename": filename,
        "Verdict": verdict,
        "Confidence (%)": round(confidence, 2),
    }])
    history = pd.concat([history, new_row], ignore_index=True)
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    history.to_csv(HISTORY_PATH, index=False)
    return history


def run_scan(uploaded_file, model, required_features):
    # pefile needs a real file path, so write the upload to a temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    try:
        raw_features = extract_features(tmp_path)
        df = pd.DataFrame([raw_features])
        df = df.reindex(columns=required_features, fill_value=0)

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0]
        confidence = max(probability) * 100
        verdict = "MALICIOUS" if prediction == 1 else "BENIGN"

        return verdict, confidence, raw_features
    finally:
        os.remove(tmp_path)


# --- UI ---
st.title("🛡️ AI Malware Detection Agent")
st.caption("Static PE-header analysis using a Random Forest classifier — 100% offline, no signatures.")

model, required_features = load_model_and_features()

uploaded_file = st.file_uploader("Upload a Windows executable (.exe)", type=["exe"])

if uploaded_file is not None:
    with st.spinner("Extracting PE header features and running prediction..."):
        verdict, confidence, raw_features = run_scan(uploaded_file, model, required_features)

    st.divider()

    col1, col2 = st.columns([1, 2])
    with col1:
        if verdict == "MALICIOUS":
            st.error(f"### 🚨 {verdict}")
        else:
            st.success(f"### ✅ {verdict}")
        st.metric("Confidence", f"{confidence:.2f}%")
        st.caption(f"File: `{uploaded_file.name}`")

        missing = set(required_features) - set(raw_features.keys())
        if missing:
            st.warning(f"{len(missing)} features zero-filled: {missing}")
        else:
            st.info("All 77 features extracted successfully — no zero-fill.")

    with col2:
        st.subheader("Full Feature Report (all 77 extracted values)")
        feature_df = pd.DataFrame(
            [(k, v) for k, v in raw_features.items()],
            columns=["Feature", "Value"]
        )
        st.dataframe(feature_df, use_container_width=True, height=400)

    save_to_history(uploaded_file.name, verdict, confidence)

st.divider()

st.subheader("📜 Scan History")
history = load_history()
if history.empty:
    st.caption("No scans yet — upload a file above to get started.")
else:
    st.dataframe(
        history.sort_values("Timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
    )
    if st.button("Clear history"):
        os.remove(HISTORY_PATH)
        st.rerun()