import os
import math
import re
from collections import Counter
import joblib

MODEL_PATH = "models/malware_model.pkl"


def calculate_entropy(data):
    if not data:
        return 0.0
    freq = Counter(data)
    probs = [v / len(data) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception:
        return None

    file_size = os.path.getsize(file_path)
    entropy = calculate_entropy(data)
    strings_count = len(re.findall(rb"[ -~]{4,}", data))

    is_exe = 1 if file_path.lower().endswith(".exe") else 0
    suspicious_ext = 1 if (".exe" in file_path.lower() and not file_path.lower().endswith(".exe")) else 0

    return [
        file_size,
        entropy,
        strings_count,
        is_exe,
        suspicious_ext
    ]


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("ML model not found. Train the model first.")
    return joblib.load(MODEL_PATH)


def predict(file_path):
    model = load_model()
    features = extract_features(file_path)

    if features is None:
        return 0.0

    probability = model.predict_proba([features])[0][1]
    return round(probability * 100, 2)
