import json
import joblib
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FEATURES_PATH = (
    PROJECT_ROOT
    / "ML Models"
    / "XGBoost"
    / "sentinel_feature_columns_v1.joblib"
)

feature_columns = joblib.load(FEATURES_PATH)

# Synthetic sample purely for testing the API pipeline
features = {feature: 0.0 for feature in feature_columns}

payload = json.dumps({
    "features": features
}).encode("utf-8")

request = urllib.request.Request(
    "http://127.0.0.1:8000/predict",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST"
)

with urllib.request.urlopen(request) as response:
    result = json.loads(response.read().decode("utf-8"))

print(json.dumps(result, indent=2))