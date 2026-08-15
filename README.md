# AI Malware Detection Agent (MDA)

A malware detection tool that uses machine learning instead of traditional signature-based scanning. Rather than checking a file against a database of known malware hashes, it looks at the structural properties of a Windows executable's PE header and predicts whether the file is malicious based on patterns learned from a labeled dataset.

## Why this approach

Signature-based antivirus only catches malware it has already seen before. This project instead trains a Random Forest classifier on structural features extracted from PE headers — things like section entropy, imported function names, and header characteristics — so it can flag files based on how they're built, not just whether they match a known bad hash.

## What it does

- Extracts 77 structural features from any Windows `.exe` file using `pefile`
- Runs those features through a trained Random Forest model to get a malicious/benign verdict with a confidence score
- Provides a Streamlit dashboard for uploading a file and seeing the full breakdown, plus a scan history log
- Runs as a background watchdog that monitors a folder and automatically moves flagged files into quarantine

## Project structure
MDA/
├── data/ dataset and test files
├── models/ trained model and feature schema (.pkl files)
├── src/
│ └── extractor.py PE feature extraction logic
├── app.py Streamlit dashboard
├── predict.py command-line single-file scan
├── train_model.py trains and saves the model
├── watchdog_agent.py folder monitor / auto-quarantine
└── requirements.txt
## How it works

**Training** — `train_model.py` loads the labeled dataset, trains a Random Forest on 100 trees, and saves both the model and the exact list of 77 feature columns it expects.
**Extraction** — `src/extractor.py` takes a real `.exe` file and computes all 77 features using `pefile`: DOS/COFF/Optional header fields directly, plus derived values like min/max section entropy and counts of suspicious imported functions.
**Prediction** — `predict.py` and `app.py` both feed extracted features into the trained model and return a verdict with confidence.
**Monitoring** — `watchdog_agent.py` watches a folder continuously. Any new `.exe` gets scanned automatically, and anything flagged malicious above a confidence threshold gets moved to `quarantine/`.
## Setup
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
## Usage
Train the model:
```bash
python train_model.py
```
Scan a single file:
```bash
python predict.py path/to/file.exe
```
Launch the dashboard:
```bash
streamlit run app.py
```
Start the watchdog:
```bash
python watchdog_agent.py
```
## Results
The model reaches about 99% accuracy on a held-out test split. That number reflects performance on data from the same distribution as training, though — it's not a guarantee against novel, deliberately evasive malware. Static header analysis alone also has limits; real antivirus products combine this kind of static analysis with dynamic/behavioral checks, which this project doesn't attempt.
One thing worth noting: the training data is imbalanced (roughly 75% malware, 25% benign), which is why benign verdicts currently come back with moderate confidence (around 70-75%) rather than very high. This can be improved by weighting classes during training.
## Dataset
[SOMLAP DATA SET: Windows PE Header Malware Dataset](https://www.kaggle.com/datasets/ravikiranvarmap/somlap-data-set), via Kaggle.