from __future__ import annotations

from pathlib import Path

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"

FEATURES_PATH = ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
ATTACK_DATASET = ROOT / "Dataset" / "CIC-IDS2017" / "DDoS-Friday-no-metadata.parquet"

TIMEOUT = 15.0

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed

    print(f"[{'PASS' if condition else 'FAIL'}] {name}")

    if detail:
        print(f"       {detail}")

    if condition:
        passed += 1
    else:
        failed += 1


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


def load_genuine_attack_row(
    path: Path,
    feature_names: list[str],
) -> dict[str, float]:
    df = pd.read_parquet(path)
    label_col = find_label_column(df)

    labels = df[label_col].map(label_to_binary)
    features = df.loc[:, feature_names].apply(pd.to_numeric, errors="coerce")

    values = features.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)

    candidates = features.loc[finite_mask & (labels == 1)]

    if candidates.empty:
        raise RuntimeError("No finite ATTACK row found.")

    row = candidates.iloc[0]

    return {name: float(row[name]) for name in feature_names}


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 6A")
    print("POSTGRESQL OUTAGE / SAFE-FAILURE VALIDATION")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 production features, found {len(feature_names)}."
        )

    attack_features = load_genuine_attack_row(
        ATTACK_DATASET,
        feature_names,
    )

    with httpx.Client(timeout=TIMEOUT) as client:
        try:
            health_response = client.get(BASE_URL + "/health")
            health = health_response.json()
        except Exception as exc:
            print(f"\nERROR: FastAPI is not reachable at {BASE_URL}: {exc}")
            return 2

        check(
            "FastAPI remains reachable while PostgreSQL is stopped",
            health_response.status_code == 200,
            f"status={health_response.status_code} body={health}",
        )

        try:
            system_response = client.get(BASE_URL + "/system/status")
            system = system_response.json()
        except Exception as exc:
            print(f"\nERROR: /system/status could not be read. Details: {exc}")
            return 3

        if system.get("database") != "OFFLINE":
            print("\nSTOP: PostgreSQL is not OFFLINE yet.")
            print(
                "Stop the PostgreSQL service first, wait a few seconds, "
                "then run this validator again."
            )
            print(f"Current status: {system}")
            return 4

        check(
            "System health reports PostgreSQL OFFLINE",
            system_response.status_code == 200
            and system.get("database") == "OFFLINE",
            str(system),
        )

        payload = {
            "features": attack_features,
            "metadata": {
                "source_ip": "198.51.100.90",
                "destination_ip": "192.0.2.90",
                "source_port": 59000,
                "destination_port": 443,
                "transport_protocol": "TCP",
            },
            "trigger_automation": False,
        }

        predict_response = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        try:
            predict_body = predict_response.json()
        except Exception:
            predict_body = predict_response.text

        check(
            "Prediction request fails explicitly instead of claiming persistence success",
            predict_response.status_code == 500,
            f"status={predict_response.status_code} body={predict_body}",
        )

        detail = (
            predict_body.get("detail")
            if isinstance(predict_body, dict)
            else None
        )

        check(
            "Failure message identifies detection persistence failure",
            detail == "Prediction succeeded, but saving detection failed.",
            f"detail={detail}",
        )

        health_response_2 = client.get(BASE_URL + "/health")

        check(
            "FastAPI process remains alive after failed database write",
            health_response_2.status_code == 200,
            f"status={health_response_2.status_code}",
        )

        system_response_2 = client.get(BASE_URL + "/system/status")
        system_2 = system_response_2.json()

        check(
            "PostgreSQL remains accurately reported OFFLINE after failed write",
            system_response_2.status_code == 200
            and system_2.get("database") == "OFFLINE",
            str(system_2),
        )

    print("\n" + "=" * 80)
    print("STEP 6A RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel failed safely: FastAPI remained alive, "
            "PostgreSQL was reported OFFLINE, and /predict returned an explicit "
            "500 instead of pretending the detection was persisted."
        )
        print("\nRestart PostgreSQL after this test.")
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
