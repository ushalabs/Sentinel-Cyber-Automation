from __future__ import annotations

from pathlib import Path

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"

FEATURES_PATH = ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
BENIGN_DATASET = ROOT / "Dataset" / "CIC-IDS2017" / "Benign-Monday-no-metadata.parquet"

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


def load_genuine_benign_row(path: Path, feature_names: list[str]) -> dict[str, float]:
    df = pd.read_parquet(path)
    label_col = find_label_column(df)
    labels = df[label_col].map(label_to_binary)
    features = df.loc[:, feature_names].apply(pd.to_numeric, errors="coerce")
    values = features.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)
    candidates = features.loc[finite_mask & (labels == 0)]
    if candidates.empty:
        raise RuntimeError("No finite BENIGN row found.")
    row = candidates.iloc[0]
    return {name: float(row[name]) for name in feature_names}


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 6B")
    print("POSTGRESQL RECOVERY / RECONNECTION VALIDATION")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))
    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 production features, found {len(feature_names)}."
        )

    benign_features = load_genuine_benign_row(BENIGN_DATASET, feature_names)

    with httpx.Client(timeout=TIMEOUT) as client:
        try:
            system_response = client.get(BASE_URL + "/system/status")
            system = system_response.json()
        except Exception as exc:
            print(f"\nERROR: FastAPI is not reachable at {BASE_URL}: {exc}")
            return 2

        if system.get("database") != "ONLINE":
            print("\nSTOP: PostgreSQL is not ONLINE yet.")
            print(
                "Start the PostgreSQL service, wait a few seconds, "
                "then run this validator again."
            )
            print(f"Current status: {system}")
            return 3

        check(
            "System health reports PostgreSQL ONLINE after restart",
            system_response.status_code == 200 and system.get("database") == "ONLINE",
            str(system),
        )

        stats_response = client.get(BASE_URL + "/dashboard/stats")
        check(
            "Dashboard database queries recover after PostgreSQL restart",
            stats_response.status_code == 200,
            f"status={stats_response.status_code}",
        )

        payload = {
            "features": benign_features,
            "metadata": {
                "source_ip": "192.0.2.101",
                "destination_ip": "192.0.2.102",
                "source_port": 60000,
                "destination_port": 443,
                "transport_protocol": "TCP",
            },
            "trigger_automation": False,
        }

        predict_response = client.post(BASE_URL + "/predict", json=payload)
        try:
            predict_body = predict_response.json()
        except Exception:
            predict_body = predict_response.text

        detection_id = (
            predict_body.get("detection_id")
            if isinstance(predict_body, dict)
            else None
        )

        check(
            "Prediction endpoint accepts writes again after PostgreSQL restart",
            predict_response.status_code == 200 and detection_id is not None,
            f"status={predict_response.status_code} body={predict_body}",
        )

        check(
            "Recovery validation row is classified BENIGN",
            (
                isinstance(predict_body, dict)
                and predict_body.get("prediction") == "BENIGN"
                and predict_body.get("attack") is False
            ),
            str(predict_body),
        )

        if detection_id is not None:
            detail_response = client.get(BASE_URL + f"/detections/{detection_id}")
            detail = detail_response.json()

            check(
                "Recovered database persists and reads the new detection",
                (
                    detail_response.status_code == 200
                    and detail.get("id") == detection_id
                    and detail.get("prediction") == "BENIGN"
                    and detail.get("source_ip") == "192.0.2.101"
                ),
                str(
                    {
                        "id": detail.get("id"),
                        "prediction": detail.get("prediction"),
                        "source_ip": detail.get("source_ip"),
                    }
                ),
            )

        system_response_2 = client.get(BASE_URL + "/system/status")
        system_2 = system_response_2.json()

        check(
            "PostgreSQL remains ONLINE after recovered read/write traffic",
            (
                system_response_2.status_code == 200
                and system_2.get("database") == "ONLINE"
            ),
            str(system_2),
        )

    print("\n" + "=" * 80)
    print("STEP 6B RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel recovered cleanly after PostgreSQL restart. "
            "Existing FastAPI process reused the database layer successfully "
            "for health checks, dashboard reads, and a new persisted detection."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
