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
    "features": features,
    "metadata": {
        "source_ip": "203.0.113.50",
        "destination_ip": "192.168.1.10",
        "source_port": 51542,
        "destination_port": 22,
        "transport_protocol": "TCP",
        "observed_at": "2026-09-20T13:05:00+05:00"
    }
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