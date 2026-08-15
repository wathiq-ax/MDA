"""
Week 5: The Watchdog Agent
Monitors a target folder (e.g. Downloads) for new .exe files, scans them,
and automatically quarantines anything flagged MALICIOUS.
"""

import os
import sys
import time
import shutil
import joblib
import pandas as pd
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.extractor import extract_features

MODEL_PATH = "models/malware_brain.pkl"
FEATURES_PATH = "models/features.pkl"
QUARANTINE_DIR = "quarantine"
LOG_PATH = "data/watchdog_log.csv"

# ⚠️ START WITH A TEST FOLDER, not your real Downloads, until you trust this.
# Example: WATCH_FOLDER = r"C:\Users\ProTech\OneDrive\Desktop\MDA\data\test_downloads"
WATCH_FOLDER = r"C:\Users\ProTech\OneDrive\Desktop\MDA\data\test_downloads"

CONFIDENCE_THRESHOLD = 70.0  # only auto-quarantine if confidence >= this


def wait_until_file_ready(filepath, timeout=15):
    """Wait until a file's size stops changing (download/copy finished)."""
    last_size = -1
    stable_count = 0
    start = time.time()
    while time.time() - start < timeout:
        try:
            size = os.path.getsize(filepath)
        except OSError:
            time.sleep(0.5)
            continue
        if size == last_size:
            stable_count += 1
            if stable_count >= 3:
                return True
        else:
            stable_count = 0
        last_size = size
        time.sleep(0.5)
    return False


def log_event(filename, verdict, confidence, action):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    row = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Filename": filename,
        "Verdict": verdict,
        "Confidence (%)": round(confidence, 2),
        "Action": action,
    }])
    if os.path.exists(LOG_PATH):
        row.to_csv(LOG_PATH, mode="a", header=False, index=False)
    else:
        row.to_csv(LOG_PATH, index=False)


class ExeWatcher(FileSystemEventHandler):
    def __init__(self, model, required_features):
        self.model = model
        self.required_features = required_features

    def on_created(self, event):
        if event.is_directory:
            return
        if not event.src_path.lower().endswith(".exe"):
            return

        filepath = event.src_path
        filename = os.path.basename(filepath)
        print(f"\n[*] New file detected: {filename}")
        print("[*] Waiting for download/copy to finish...")

        if not wait_until_file_ready(filepath):
            print(f"[!] Timed out waiting for {filename} to stabilize. Skipping.")
            return

        try:
            print("[*] Extracting PE features...")
            raw_features = extract_features(filepath)
            df = pd.DataFrame([raw_features])
            df = df.reindex(columns=self.required_features, fill_value=0)

            prediction = self.model.predict(df)[0]
            probability = self.model.predict_proba(df)[0]
            confidence = max(probability) * 100
            verdict = "MALICIOUS" if prediction == 1 else "BENIGN"

            print(f"[*] Verdict: {verdict} ({confidence:.2f}% confidence)")

            if verdict == "MALICIOUS" and confidence >= CONFIDENCE_THRESHOLD:
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
                dest = os.path.join(QUARANTINE_DIR, filename)
                shutil.move(filepath, dest)
                print(f"[QUARANTINED] Moved {filename} -> {QUARANTINE_DIR}/")
                log_event(filename, verdict, confidence, "QUARANTINED")
            else:
                print(f"[OK] {filename} left in place.")
                log_event(filename, verdict, confidence, "ALLOWED")

        except Exception as e:
            print(f"[!] Error scanning {filename}: {e}")
            log_event(filename, "ERROR", 0, f"SCAN_FAILED: {e}")


def main():
    print("=" * 60)
    print("  AI MALWARE DETECTION AGENT — Watchdog Mode")
    print("=" * 60)
    print(f"[*] Monitoring folder: {WATCH_FOLDER}")
    print(f"[*] Quarantine folder: {QUARANTINE_DIR}")
    print(f"[*] Confidence threshold for auto-quarantine: {CONFIDENCE_THRESHOLD}%")
    print("[*] Press Ctrl+C to stop.\n")

    if not os.path.isdir(WATCH_FOLDER):
        print(f"[!] ERROR: Watch folder does not exist: {WATCH_FOLDER}")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    required_features = joblib.load(FEATURES_PATH)

    event_handler = ExeWatcher(model, required_features)
    observer = Observer()
    observer.schedule(event_handler, WATCH_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Watchdog stopped.")
    observer.join()


if __name__ == "__main__":
    main()