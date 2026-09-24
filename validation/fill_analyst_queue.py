from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 90.0

FEATURES_PATH = (
    ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
)

ATTACK_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "DDoS-Friday-no-metadata.parquet"
)

# Public IPs used only as metadata/context for Sentinel enrichment.
# This script DOES NOT send malicious traffic to these IPs.
TEST_CASES = [
    {
        "label": "Google DNS context",
        "source_ip": "8.8.8.8",
        "destination_ip": "192.0.2.50",
        "source_port": 58000,
        "destination_port": 443,
        "transport_protocol": "TCP",
    },
    {
        "label": "Cloudflare DNS context",
        "source_ip": "1.1.1.1",
        "destination_ip": "192.0.2.51",
        "source_port": 58100,
        "destination_port": 80,
        "transport_protocol": "TCP",
    },
    {
        "label": "Quad9 DNS context",
        "source_ip": "9.9.9.9",
        "destination_ip": "192.0.2.52",
        "source_port": 58200,
        "destination_port": 22,
        "transport_protocol": "TCP",
    },
    {
        "label": "OpenDNS context",
        "source_ip": "208.67.222.222",
        "destination_ip": "192.0.2.53",
        "source_port": 58300,
        "destination_port": 3389,
        "transport_protocol": "TCP",
    },
]


def find_label_column(df: pd.DataFrame) -> str:
    for candidate in ("Label", "label", "Class", "class", "Target", "target"):
        if candidate in df.columns:
            return candidate
    raise RuntimeError("Could not find dataset label column.")


def label_to_binary(value) -> int:
    text = str(value).strip().upper()
    if text in {"BENIGN", "NORMAL", "0", "0.0"}:
        return 0
    return 1


def load_attack_row(feature_names: list[str]) -> dict[str, float]:
    df = pd.read_parquet(ATTACK_DATASET)
    label_col = find_label_column(df)

    labels = df[label_col].map(label_to_binary)
    feature_df = df.loc[:, feature_names].apply(
        pd.to_numeric,
        errors="coerce",
    )

    values = feature_df.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)

    candidates = feature_df.loc[finite_mask & (labels == 1)]

    if candidates.empty:
        raise RuntimeError("No finite ATTACK row found.")

    row = candidates.iloc[0]

    return {
        name: float(row[name])
        for name in feature_names
    }


def main() -> int:
    print("=" * 80)
    print("SENTINEL - FILL ANALYST QUEUE WITH CONTROLLED ATTACK REPLAYS")
    print("=" * 80)
    print(
        "These are controlled CIC-IDS2017 feature replays. "
        "No malicious network traffic is generated."
    )
    print()

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 production features, found {len(feature_names)}."
        )

    attack_features = load_attack_row(feature_names)

    created_ids: list[int] = []

    with httpx.Client(timeout=TIMEOUT) as client:
        status = client.get(BASE_URL + "/system/status").json()

        print("System:", status)
        print()

        for index, case in enumerate(TEST_CASES, start=1):
            request_id = (
                f"readme-attack-{index}-"
                + uuid4().hex
            )

            payload = {
                "request_id": request_id,
                "features": attack_features,
                "metadata": {
                    "source_ip": case["source_ip"],
                    "destination_ip": case["destination_ip"],
                    "source_port": case["source_port"],
                    "destination_port": case["destination_port"],
                    "transport_protocol": case["transport_protocol"],
                },
                "trigger_automation": True,
            }

            print(
                f"[{index}/{len(TEST_CASES)}] {case['label']} "
                f"({case['source_ip']})"
            )

            response = client.post(
                BASE_URL + "/predict",
                json=payload,
            )

            try:
                body = response.json()
            except Exception:
                body = response.text

            if response.status_code != 200:
                print(
                    f"  FAILED: HTTP {response.status_code} "
                    f"{body}"
                )
                continue

            detection_id = body.get("detection_id")
            created_ids.append(detection_id)

            print(
                f"  Detection #{detection_id}: "
                f"{body.get('prediction')} "
                f"confidence={body.get('confidence')}"
            )
            print(
                f"  Automation triggered: "
                f"{body.get('automation_triggered')}"
            )

            # Small gap so external services are not hit simultaneously.
            time.sleep(2)

        print()
        print("=" * 80)
        print("CREATED ATTACK DETECTIONS")
        print("=" * 80)
        print(created_ids)
        print()
        print(
            "Do NOT approve/reject/dismiss these yet if you want the "
            "Analyst Queue to remain populated for README screenshots."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
