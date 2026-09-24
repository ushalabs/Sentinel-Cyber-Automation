from __future__ import annotations

from pathlib import Path

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"

FEATURES_PATH = (
    ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
)

BENIGN_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "Benign-Monday-no-metadata.parquet"
)

TIMEOUT = 15.0


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


def load_genuine_benign_row(
    path: Path,
    feature_names: list[str],
) -> dict[str, float]:
    df = pd.read_parquet(path)
    label_col = find_label_column(df)

    labels = df[label_col].map(label_to_binary)

    features = df.loc[:, feature_names].apply(
        pd.to_numeric,
        errors="coerce",
    )

    values = features.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)

    candidates = features.loc[
        finite_mask & (labels == 0)
    ]

    if candidates.empty:
        raise RuntimeError("No finite BENIGN row found.")

    row = candidates.iloc[0]

    return {
        name: float(row[name])
        for name in feature_names
    }


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 9A")
    print("DUPLICATE / RETRY IDEMPOTENCY DIAGNOSTIC")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 production features, found {len(feature_names)}."
        )

    benign_features = load_genuine_benign_row(
        BENIGN_DATASET,
        feature_names,
    )

    payload = {
        "features": benign_features,
        "metadata": {
            "source_ip": "192.0.2.201",
            "destination_ip": "192.0.2.202",
            "source_port": 61000,
            "destination_port": 443,
            "transport_protocol": "TCP",
        },
        # Absolutely no n8n/AbuseIPDB/Gemini side effects.
        "trigger_automation": False,
    }

    with httpx.Client(timeout=TIMEOUT) as client:
        health = client.get(BASE_URL + "/system/status")
        health.raise_for_status()
        system = health.json()

        print(f"[INFO] System status: {system}")

        if system.get("database") != "ONLINE":
            print("\nSTOP: PostgreSQL must be ONLINE for this test.")
            return 2

        print("\nSending the EXACT same prediction request twice...\n")

        first = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        second = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        try:
            first_body = first.json()
        except Exception:
            first_body = first.text

        try:
            second_body = second.json()
        except Exception:
            second_body = second.text

        print(f"Request 1 status: {first.status_code}")
        print(f"Request 1 body  : {first_body}\n")

        print(f"Request 2 status: {second.status_code}")
        print(f"Request 2 body  : {second_body}\n")

        if first.status_code != 200 or second.status_code != 200:
            print("STATUS : INCONCLUSIVE")
            print(
                "\nOne or both requests failed, so duplicate behavior "
                "could not be measured cleanly."
            )
            return 3

        first_id = first_body.get("detection_id")
        second_id = second_body.get("detection_id")

        print("=" * 80)
        print("STEP 9A DIAGNOSTIC RESULT")
        print("=" * 80)

        if first_id == second_id:
            print("STATUS : IDEMPOTENT")
            print(
                f"\nBoth retries resolved to the same detection_id={first_id}."
            )
            return 0

        print("STATUS : IDEMPOTENCY GAP CONFIRMED")
        print(
            f"\nThe same request created TWO detections: "
            f"{first_id} and {second_id}."
        )
        print(
            "This means a client retry can currently duplicate database records. "
            "Because automation is disabled here, no n8n/AbuseIPDB/Gemini side "
            "effects were triggered."
        )
        print(
            "\nDo NOT treat this as a failed project test. "
            "This diagnostic is meant to expose whether hardening is required."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
