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

TIMEOUT = 25.0

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
    print("SENTINEL PHASE 10 - STEP 5C")
    print("GEMINI FAILURE / ANALYSIS-STATE VALIDATION")
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

        if system.get("n8n") != "ONLINE":
            print("\nSTOP: n8n must be ONLINE for this test.")
            print(f"Current status: {system}")
            return 3

        check(
            "System health reports n8n ONLINE",
            system.get("n8n") == "ONLINE",
            str(system),
        )

        payload = {
            "features": attack_features,
            "metadata": {
                "source_ip": "8.8.8.8",
                "destination_ip": "192.0.2.70",
                "source_port": 58000,
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
            "Prediction endpoint survives Gemini failure",
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
            "Gemini/n8n workflow failure is surfaced as automation error",
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
                "ATTACK detection remains persisted",
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
                "AbuseIPDB enrichment is preserved before Gemini failure",
                (
                    detail.get("threat_provider") == "AbuseIPDB"
                    and detail.get("threat_intelligence") is not None
                    and detail.get("enriched_at") is not None
                ),
                str(
                    {
                        "threat_provider": detail.get("threat_provider"),
                        "enriched_at": detail.get("enriched_at"),
                    }
                ),
            )

            check(
                "Gemini failure is persisted as analysis_status=FAILED",
                (
                    detail.get("analysis_status") == "FAILED"
                    and bool(detail.get("analysis_error"))
                ),
                str(
                    {
                        "analysis_status": detail.get("analysis_status"),
                        "analysis_error": detail.get("analysis_error"),
                    }
                ),
            )

            check(
                "Failed Gemini call does not create fake incident analysis",
                (
                    detail.get("incident_analysis") is None
                    and detail.get("analyzed_at") is None
                ),
                str(
                    {
                        "incident_analysis": detail.get("incident_analysis"),
                        "analyzed_at": detail.get("analyzed_at"),
                    }
                ),
            )

            check(
                "Failed analysis does not advance to human review",
                detail.get("review_status") == "NOT_REQUIRED",
                f"review_status={detail.get('review_status')}",
            )

            queue_response = client.get(
                BASE_URL + "/dashboard/attention?limit=50"
            )

            queue = queue_response.json()

            queue_item = next(
                (
                    item
                    for item in queue
                    if isinstance(item, dict)
                    and item.get("id") == detection_id
                ),
                None,
            )

            check(
                "Failed analysis appears in Analyst Queue as ANALYSIS_FAILED",
                (
                    queue_response.status_code == 200
                    and queue_item is not None
                    and queue_item.get("attention_state") == "ANALYSIS_FAILED"
                ),
                f"queue_item={queue_item}",
            )

    print("\n" + "=" * 80)
    print("STEP 5C RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel preserved the ATTACK and AbuseIPDB evidence, explicitly "
            "marked LLM analysis as FAILED, withheld human review, and surfaced "
            "the failed incident in the Analyst Queue."
        )
        print(
            "\nIMPORTANT: restore the real GEMINI_API_KEY and restart FastAPI "
            "before continuing."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
