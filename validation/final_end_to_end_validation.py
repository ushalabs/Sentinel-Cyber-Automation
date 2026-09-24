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
TIMEOUT = 30.0
POLL_SECONDS = 45
POLL_INTERVAL = 2

FEATURES_PATH = (
    ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
)

ATTACK_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "DDoS-Friday-no-metadata.parquet"
)

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


def get_detection(
    client: httpx.Client,
    detection_id: int,
) -> dict:
    response = client.get(
        BASE_URL + f"/detections/{detection_id}"
    )
    response.raise_for_status()
    return response.json()


def wait_for_analysis(
    client: httpx.Client,
    detection_id: int,
) -> dict:
    deadline = time.time() + POLL_SECONDS
    last = {}

    while time.time() < deadline:
        last = get_detection(
            client,
            detection_id,
        )

        status = last.get("analysis_status")

        if status in {"COMPLETED", "FAILED"}:
            return last

        time.sleep(POLL_INTERVAL)

    return last


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 11")
    print("FINAL END-TO-END VALIDATION")
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

    request_id = "phase10-final-" + uuid4().hex

    payload = {
        "request_id": request_id,
        "features": attack_features,
        "metadata": {
            "source_ip": "8.8.8.8",
            "destination_ip": "192.0.2.250",
            "source_port": 65000,
            "destination_port": 443,
            "transport_protocol": "TCP",
        },
        "trigger_automation": True,
    }

    with httpx.Client(timeout=TIMEOUT) as client:
        # --------------------------------------------------------------
        # Preflight
        # --------------------------------------------------------------
        system_response = client.get(
            BASE_URL + "/system/status"
        )
        system = system_response.json()

        check(
            "Core system preflight is healthy",
            (
                system_response.status_code == 200
                and system.get("api") == "ONLINE"
                and system.get("database") == "ONLINE"
                and system.get("model") == "LOADED"
                and system.get("n8n") == "ONLINE"
            ),
            str(system),
        )

        # --------------------------------------------------------------
        # New ATTACK -> DB -> n8n -> AbuseIPDB -> Gemini
        # --------------------------------------------------------------
        predict_response = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        try:
            prediction = predict_response.json()
        except Exception:
            prediction = predict_response.text

        check(
            "Final replay request returns HTTP 200",
            predict_response.status_code == 200,
            f"status={predict_response.status_code} body={prediction}",
        )

        check(
            "Genuine CIC-IDS2017 DDoS row is classified ATTACK",
            (
                isinstance(prediction, dict)
                and prediction.get("prediction") == "ATTACK"
                and prediction.get("attack") is True
                and prediction.get("request_id") == request_id
                and prediction.get("idempotent_replay") is False
            ),
            str(prediction),
        )

        check(
            "ATTACK triggers the production automation workflow",
            (
                isinstance(prediction, dict)
                and prediction.get("automation_triggered") is True
            ),
            str(
                prediction.get("automation_result")
                if isinstance(prediction, dict)
                else prediction
            ),
        )

        detection_id = (
            prediction.get("detection_id")
            if isinstance(prediction, dict)
            else None
        )

        if detection_id is None:
            print("\nSTOP: No detection_id returned.")
            return 2

        detail = wait_for_analysis(
            client,
            detection_id,
        )

        check(
            "Threat intelligence is persisted before analysis",
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
            "Gemini incident analysis completes successfully",
            (
                detail.get("analysis_status") == "COMPLETED"
                and detail.get("incident_analysis") is not None
                and detail.get("analysis_error") is None
                and detail.get("analyzed_at") is not None
            ),
            str(
                {
                    "analysis_status": detail.get("analysis_status"),
                    "severity": (
                        detail.get("incident_analysis") or {}
                    ).get("severity"),
                    "analysis_error": detail.get("analysis_error"),
                }
            ),
        )

        check(
            "Completed analysis advances incident to human review",
            detail.get("review_status") == "PENDING",
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
            "Incident appears in Analyst Queue as PENDING_REVIEW",
            (
                queue_response.status_code == 200
                and queue_item is not None
                and queue_item.get("attention_state") == "PENDING_REVIEW"
            ),
            f"queue_item={queue_item}",
        )

        # --------------------------------------------------------------
        # Human approval -> safe simulation response
        # --------------------------------------------------------------
        review_response = client.post(
            BASE_URL + f"/detections/{detection_id}/review",
            json={
                "decision": "APPROVE",
                "action": "LOG_ONLY",
                "note": "Phase 10 final end-to-end validation",
            },
        )

        review = review_response.json()

        check(
            "Human approval with allowlisted LOG_ONLY action succeeds",
            (
                review_response.status_code == 200
                and review.get("review_status") == "APPROVED"
                and review.get("response_action") == "LOG_ONLY"
                and review.get("response_status") == "PENDING"
            ),
            f"status={review_response.status_code} body={review}",
        )

        respond_response = client.post(
            BASE_URL + f"/detections/{detection_id}/respond"
        )

        try:
            response_body = respond_response.json()
        except Exception:
            response_body = respond_response.text

        response_result = (
            response_body.get("response_result")
            if isinstance(response_body, dict)
            else None
        )

        check(
            "Approved response executes successfully",
            (
                respond_response.status_code == 200
                and isinstance(response_body, dict)
                and response_body.get("response_status") == "EXECUTED"
            ),
            f"status={respond_response.status_code} body={response_body}",
        )

        check(
            "Response remains safely in SIMULATION mode",
            (
                isinstance(response_result, dict)
                and response_result.get("mode") == "SIMULATION"
                and response_result.get("action") == "LOG_ONLY"
                and response_result.get("executed") is True
            ),
            f"response_result={response_result}",
        )

        final_detail = get_detection(
            client,
            detection_id,
        )

        check(
            "Final review/response state is persisted",
            (
                final_detail.get("review_status") == "APPROVED"
                and final_detail.get("response_action") == "LOG_ONLY"
                and final_detail.get("response_status") == "EXECUTED"
                and final_detail.get("response_result") is not None
                and final_detail.get("responded_at") is not None
            ),
            str(
                {
                    "review_status": final_detail.get("review_status"),
                    "response_action": final_detail.get("response_action"),
                    "response_status": final_detail.get("response_status"),
                    "responded_at": final_detail.get("responded_at"),
                }
            ),
        )

        # --------------------------------------------------------------
        # Retry the exact same request after the full pipeline completed.
        # It must return the same detection and NOT re-run automation.
        # --------------------------------------------------------------
        retry_response = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        retry = retry_response.json()

        check(
            "Post-completion retry resolves to the same detection",
            (
                retry_response.status_code == 200
                and retry.get("detection_id") == detection_id
                and retry.get("request_id") == request_id
                and retry.get("idempotent_replay") is True
            ),
            str(retry),
        )

        check(
            "Post-completion retry does not re-run n8n automation",
            (
                retry.get("automation_triggered") is False
                and isinstance(
                    retry.get("automation_result"),
                    dict,
                )
                and retry["automation_result"].get("status") == "skipped"
            ),
            str(retry.get("automation_result")),
        )

        latest_detail = get_detection(
            client,
            detection_id,
        )

        check(
            "Retry does not disturb the completed incident state",
            (
                latest_detail.get("analysis_status") == "COMPLETED"
                and latest_detail.get("review_status") == "APPROVED"
                and latest_detail.get("response_status") == "EXECUTED"
            ),
            str(
                {
                    "analysis_status": latest_detail.get("analysis_status"),
                    "review_status": latest_detail.get("review_status"),
                    "response_status": latest_detail.get("response_status"),
                }
            ),
        )

    print("\n" + "=" * 80)
    print("STEP 11 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel passed the final controlled end-to-end validation: "
            "genuine CIC-IDS2017 attack inference, persistence, n8n orchestration, "
            "AbuseIPDB enrichment, Gemini analysis, Analyst Queue routing, human "
            "approval, allowlisted simulated response, and post-completion "
            "idempotent retry behavior all worked together."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
