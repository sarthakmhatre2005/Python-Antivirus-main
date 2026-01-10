import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from engine.ml_engine import extract_features

X = []
y = []

MALWARE_DIR = "dataset/malware"
CLEAN_DIR = "dataset/clean"

print("[*] Loading malware samples...")
for file in os.listdir(MALWARE_DIR):
    path = os.path.join(MALWARE_DIR, file)
    features = extract_features(path)
    if features:
        X.append(features)
        y.append(1)

print("[*] Loading clean samples...")
for file in os.listdir(CLEAN_DIR):
    path = os.path.join(CLEAN_DIR, file)
    features = extract_features(path)
    if features:
        X.append(features)
        y.append(0)

if len(X) == 0:
    raise Exception("Dataset is empty. Add files to dataset folders.")

print("[*] Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/malware_model.pkl")

print("[✓] Model trained and saved to models/malware_model.pkl")
