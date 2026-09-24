from __future__ import annotations

import json
import time
from datetime import datetime, timezone
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

ATTACK_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "DDoS-Friday-no-metadata.parquet"
)

RESULTS_DIR = ROOT / "validation" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

REPORT_PATH = RESULTS_DIR / "phase10_step4_full_replay_report.json"

TIMEOUT = 30.0
POLL_INTERVAL = 2.0
POLL_TIMEOUT = 90.0

passed = 0
failed = 0
checks: list[dict] = []


def record_check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed

    print(f"[{'PASS' if condition else 'FAIL'}] {name}")

    if detail:
        print(f"       {detail}")

    checks.append(
        {
            "name": name,
            "passed": bool(condition),
            "detail": detail,
        }
    )

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


def load_genuine_row(
    path: Path,
    feature_names: list[str],
    wanted_class: int,
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
        finite_mask & (labels == wanted_class)
    ]

    if candidates.empty:
        raise RuntimeError(
            f"No finite class={wanted_class} row found in {path.name}"
        )

    row = candidates.iloc[0]

    return {
        name: float(row[name])
        for name in feature_names
    }


def get_json(
    client: httpx.Client,
    path: str,
):
    response = client.get(BASE_URL + path)
    response.raise_for_status()
    return response.json()


def post_json(
    client: httpx.Client,
    path: str,
    payload: dict,
):
    response = client.post(
        BASE_URL + path,
        json=payload,
    )

    try:
        body = response.json()
    except Exception:
        body = response.text

    return response, body


def poll_incident_until_terminal_analysis(
    client: httpx.Client,
    detection_id: int,
) -> dict:
    deadline = time.time() + POLL_TIMEOUT
    last = {}

    while time.time() < deadline:
        last = get_json(
            client,
            f"/detections/{detection_id}",
        )

        status = last.get("analysis_status")

        if status in {"COMPLETED", "FAILED"}:
            return last

        time.sleep(POLL_INTERVAL)

    return last


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 4")
    print("FULL BENIGN + ATTACK REPLAY VALIDATION")
    print("=" * 80)

    print(
        "\nWARNING: the ATTACK half of this test intentionally invokes "
        "the live n8n -> AbuseIPDB -> Gemini workflow."
    )
    print(
        "The BENIGN half uses trigger_automation=true too, specifically "
        "to prove the backend skips automation for BENIGN traffic."
    )

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 features, found {len(feature_names)}."
        )

    benign_features = load_genuine_row(
        BENIGN_DATASET,
        feature_names,
        wanted_class=0,
    )

    attack_features = load_genuine_row(
        ATTACK_DATASET,
        feature_names,
        wanted_class=1,
    )

    report = {
        "phase": 10,
        "step": 4,
        "test": "full_benign_and_attack_replay_validation",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "benign": {},
        "attack": {},
    }

    with httpx.Client(timeout=TIMEOUT) as client:
        # --------------------------------------------------------------
        # Preflight
        # --------------------------------------------------------------

        try:
            health = get_json(client, "/health")
        except Exception as exc:
            print(
                f"\nERROR: FastAPI is not reachable at {BASE_URL}: {exc}"
            )
            return 2

        record_check(
            "FastAPI preflight is healthy",
            (
                health.get("status") == "healthy"
                and health.get("expected_features") == 77
            ),
            str(health),
        )

        system = get_json(client, "/system/status")

        record_check(
            "PostgreSQL is ONLINE before replay",
            system.get("database") == "ONLINE",
            str(system),
        )

        record_check(
            "XGBoost is LOADED before replay",
            system.get("model") == "LOADED",
            str(system),
        )

        record_check(
            "n8n is ONLINE before ATTACK replay",
            system.get("n8n") == "ONLINE",
            str(system),
        )

        # --------------------------------------------------------------
        # Genuine BENIGN replay with automation request TRUE
        # --------------------------------------------------------------

        print("\n" + "-" * 80)
        print("BENIGN REPLAY")
        print("-" * 80)

        benign_payload = {
            "features": benign_features,
            "metadata": {
                "source_ip": "192.0.2.40",
                "destination_ip": "192.0.2.50",
                "source_port": 54000,
                "destination_port": 443,
                "transport_protocol": "TCP",
                "observed_at": datetime.now(timezone.utc).isoformat(),
            },
            # Deliberately TRUE: BENIGN should still be skipped.
            "trigger_automation": True,
        }

        response, benign_result = post_json(
            client,
            "/predict",
            benign_payload,
        )

        benign_id = (
            benign_result.get("detection_id")
            if isinstance(benign_result, dict)
            else None
        )

        report["benign"]["predict_result"] = benign_result

        record_check(
            "Genuine BENIGN replay returns HTTP 200",
            response.status_code == 200 and benign_id is not None,
            f"status={response.status_code} body={benign_result}",
        )

        record_check(
            "Genuine BENIGN replay is classified BENIGN",
            (
                isinstance(benign_result, dict)
                and benign_result.get("prediction") == "BENIGN"
                and benign_result.get("attack") is False
            ),
            str(benign_result),
        )

        record_check(
            "BENIGN is skipped by automation even when requested",
            (
                isinstance(benign_result, dict)
                and benign_result.get("automation_triggered") is False
                and isinstance(benign_result.get("automation_result"), dict)
                and benign_result["automation_result"].get("reason")
                == "BENIGN detection"
            ),
            f"automation={benign_result.get('automation_result') if isinstance(benign_result, dict) else None}",
        )

        if benign_id is not None:
            benign_detail = get_json(
                client,
                f"/detections/{benign_id}",
            )

            report["benign"]["detection"] = benign_detail

            record_check(
                "BENIGN persisted without threat intelligence or LLM analysis",
                (
                    benign_detail.get("prediction") == "BENIGN"
                    and benign_detail.get("threat_intelligence") is None
                    and benign_detail.get("incident_analysis") is None
                    and benign_detail.get("analysis_status") == "NOT_STARTED"
                    and benign_detail.get("review_status") == "NOT_REQUIRED"
                ),
                str(
                    {
                        "id": benign_id,
                        "analysis_status": benign_detail.get("analysis_status"),
                        "review_status": benign_detail.get("review_status"),
                    }
                ),
            )

        # --------------------------------------------------------------
        # Genuine DDoS ATTACK replay with LIVE automation
        # --------------------------------------------------------------

        print("\n" + "-" * 80)
        print("ATTACK REPLAY - LIVE AUTOMATION")
        print("-" * 80)

        attack_payload = {
            "features": attack_features,
            "metadata": {
                # Controlled metadata because the no-metadata Parquet file
                # contains genuine ML features but not original IP metadata.
                "source_ip": "8.8.8.8",
                "destination_ip": "192.0.2.50",
                "source_port": 55155,
                "destination_port": 443,
                "transport_protocol": "TCP",
                "observed_at": datetime.now(timezone.utc).isoformat(),
            },
            "trigger_automation": True,
        }

        response, attack_result = post_json(
            client,
            "/predict",
            attack_payload,
        )

        attack_id = (
            attack_result.get("detection_id")
            if isinstance(attack_result, dict)
            else None
        )

        report["attack"]["predict_result"] = attack_result

        record_check(
            "Genuine DDoS replay returns HTTP 200",
            response.status_code == 200 and attack_id is not None,
            f"status={response.status_code} body={attack_result}",
        )

        record_check(
            "Genuine DDoS replay is classified ATTACK",
            (
                isinstance(attack_result, dict)
                and attack_result.get("prediction") == "ATTACK"
                and attack_result.get("attack") is True
            ),
            str(attack_result),
        )

        record_check(
            "ATTACK automation is triggered",
            (
                isinstance(attack_result, dict)
                and attack_result.get("automation_triggered") is True
            ),
            f"automation={attack_result.get('automation_result') if isinstance(attack_result, dict) else None}",
        )

        if attack_id is not None:
            attack_detail = poll_incident_until_terminal_analysis(
                client,
                attack_id,
            )

            report["attack"]["detection"] = attack_detail

            record_check(
                "Threat intelligence is persisted",
                (
                    attack_detail.get("threat_provider") is not None
                    and attack_detail.get("threat_intelligence") is not None
                    and attack_detail.get("enriched_at") is not None
                ),
                str(
                    {
                        "provider": attack_detail.get("threat_provider"),
                        "enriched_at": attack_detail.get("enriched_at"),
                    }
                ),
            )

            record_check(
                "Gemini incident analysis completes",
                (
                    attack_detail.get("analysis_status") == "COMPLETED"
                    and attack_detail.get("llm_provider") is not None
                    and attack_detail.get("incident_analysis") is not None
                ),
                str(
                    {
                        "analysis_status": attack_detail.get("analysis_status"),
                        "llm_provider": attack_detail.get("llm_provider"),
                        "severity": (
                            attack_detail.get("incident_analysis") or {}
                        ).get("severity"),
                        "analysis_error": attack_detail.get("analysis_error"),
                    }
                ),
            )

            record_check(
                "Completed ATTACK is handed to human review",
                attack_detail.get("review_status") == "PENDING",
                f"review_status={attack_detail.get('review_status')}",
            )

            queue = get_json(
                client,
                "/dashboard/attention?limit=50",
            )

            queue_ids = [
                item.get("id")
                for item in queue
                if isinstance(item, dict)
            ]

            report["attack"]["analyst_queue_ids"] = queue_ids

            record_check(
                "ATTACK appears in the Analyst Queue",
                attack_id in queue_ids,
                f"attack_id={attack_id} queue_ids={queue_ids}",
            )

            if benign_id is not None:
                record_check(
                    "BENIGN does not appear in the Analyst Queue",
                    benign_id not in queue_ids,
                    f"benign_id={benign_id}",
                )

    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["passed"] = passed
    report["failed"] = failed
    report["status"] = "PASS" if failed == 0 else "CHECK FAILURES"
    report["checks"] = checks

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    print("\n" + "=" * 80)
    print("STEP 4 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")
    print(f"STATUS : {report['status']}")
    print(f"Report : {REPORT_PATH}")

    if failed == 0:
        print("\nHuman-in-the-loop checkpoint:")
        print("- Open the new ATTACK incident in the dashboard.")
        print("- Confirm its AbuseIPDB + Gemini evidence is visible.")
        print("- REJECT the Phase 10 test incident after inspection.")
        print(
            "  Rejection is intentional here: this is a controlled replay, "
            "not a real hostile live connection."
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
