from __future__ import annotations

import time
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

ATTACK_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "DDoS-Friday-no-metadata.parquet"
)

TIMEOUT = 20.0

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

    features = df.loc[:, feature_names].apply(
        pd.to_numeric,
        errors="coerce",
    )

    values = features.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)

    candidates = features.loc[
        finite_mask & (labels == 1)
    ]

    if candidates.empty:
        raise RuntimeError("No finite ATTACK row found.")

    row = candidates.iloc[0]

    return {
        name: float(row[name])
        for name in feature_names
    }


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 5A")
    print("n8n OUTAGE / GRACEFUL-DEGRADATION VALIDATION")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 features, found {len(feature_names)}."
        )

    attack_features = load_genuine_attack_row(
        ATTACK_DATASET,
        feature_names,
    )

    with httpx.Client(timeout=TIMEOUT) as client:
        try:
            system = client.get(
                BASE_URL + "/system/status"
            ).json()
        except Exception as exc:
            print(
                f"\nERROR: FastAPI is not reachable at {BASE_URL}: {exc}"
            )
            return 2

        if system.get("n8n") != "OFFLINE":
            print(
                "\nSTOP: n8n is still ONLINE."
            )
            print(
                "Close/stop n8n first, wait a few seconds, "
                "then run this validator again."
            )
            print(f"Current status: {system}")
            return 3

        check(
            "System health reports n8n OFFLINE",
            system.get("n8n") == "OFFLINE",
            str(system),
        )

        payload = {
            "features": attack_features,
            "metadata": {
                "source_ip": "198.51.100.77",
                "destination_ip": "192.0.2.50",
                "source_port": 56000,
                "destination_port": 443,
                "transport_protocol": "TCP",
            },
            "trigger_automation": True,
        }

        started = time.perf_counter()

        response = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        elapsed = time.perf_counter() - started

        try:
            result = response.json()
        except Exception:
            result = response.text

        check(
            "Prediction endpoint still returns HTTP 200 while n8n is offline",
            response.status_code == 200,
            f"status={response.status_code} elapsed={elapsed:.2f}s body={result}",
        )

        detection_id = (
            result.get("detection_id")
            if isinstance(result, dict)
            else None
        )

        check(
            "Genuine DDoS row is still classified ATTACK",
            (
                isinstance(result, dict)
                and result.get("prediction") == "ATTACK"
                and result.get("attack") is True
            ),
            str(result),
        )

        automation_result = (
            result.get("automation_result")
            if isinstance(result, dict)
            else None
        )

        check(
            "Automation failure is returned as an error instead of crashing prediction",
            (
                isinstance(result, dict)
                and result.get("automation_triggered") is False
                and isinstance(automation_result, dict)
                and bool(automation_result.get("error"))
            ),
            f"automation_result={automation_result}",
        )

        if detection_id is not None:
            detail_response = client.get(
                BASE_URL + f"/detections/{detection_id}"
            )

            detail = detail_response.json()

            check(
                "ATTACK detection is persisted despite n8n outage",
                (
                    detail_response.status_code == 200
                    and detail.get("id") == detection_id
                    and detail.get("prediction") == "ATTACK"
                ),
                str(
                    {
                        "id": detail.get("id"),
                        "prediction": detail.get("prediction"),
                    }
                ),
            )

            check(
                "Failed automation does not create fake enrichment or LLM state",
                (
                    detail.get("threat_intelligence") is None
                    and detail.get("incident_analysis") is None
                    and detail.get("analysis_status") == "NOT_STARTED"
                    and detail.get("review_status") == "NOT_REQUIRED"
                ),
                str(
                    {
                        "analysis_status": detail.get("analysis_status"),
                        "review_status": detail.get("review_status"),
                        "threat_intelligence": detail.get("threat_intelligence"),
                    }
                ),
            )

    print("\n" + "=" * 80)
    print("STEP 5A RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel degraded safely: ML inference and persistence continued, "
            "while the failed automation was surfaced without fabricating "
            "threat intelligence or LLM analysis."
        )
        print(
            "\nRestart n8n after this test."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
