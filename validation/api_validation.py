from __future__ import annotations

from pathlib import Path
import sys

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

TIMEOUT = 10.0

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed

    prefix = "PASS" if condition else "FAIL"
    print(f"[{prefix}] {name}")

    if detail:
        print(f"       {detail}")

    if condition:
        passed += 1
    else:
        failed += 1


def get_label_column(df: pd.DataFrame) -> str:
    for col in ("Label", "label", "Class", "class", "Target", "target"):
        if col in df.columns:
            return col
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
    label_col = get_label_column(df)

    labels = df[label_col].map(label_to_binary)

    feature_df = df.loc[:, feature_names].apply(
        pd.to_numeric,
        errors="coerce",
    )

    values = feature_df.to_numpy(dtype=np.float64, copy=False)
    finite_mask = np.isfinite(values).all(axis=1)

    candidates = feature_df.loc[
        finite_mask & (labels == wanted_class)
    ]

    if candidates.empty:
        raise RuntimeError(
            f"No finite class={wanted_class} rows found in {path.name}"
        )

    row = candidates.iloc[0]

    return {
        name: float(row[name])
        for name in feature_names
    }


def request_json(
    client: httpx.Client,
    method: str,
    path: str,
    **kwargs,
):
    response = client.request(method, BASE_URL + path, **kwargs)

    try:
        body = response.json()
    except Exception:
        body = response.text

    return response, body


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 2")
    print("FASTAPI CONTRACT + SAFETY-GATE VALIDATION")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))

    if len(feature_names) != 77:
        raise RuntimeError(
            f"Expected 77 production features, found {len(feature_names)}."
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

    with httpx.Client(timeout=TIMEOUT) as client:
        # ------------------------------------------------------------------
        # Basic service contract
        # ------------------------------------------------------------------

        try:
            r, body = request_json(client, "GET", "/health")
        except httpx.ConnectError:
            print(
                "\nERROR: FastAPI is not reachable at "
                f"{BASE_URL}\n"
                "Start uvicorn first, then run this validator again."
            )
            return 2

        check(
            "GET /health returns 200",
            r.status_code == 200,
            f"status={r.status_code} body={body}",
        )

        check(
            "/health reports healthy model with 77 features",
            (
                isinstance(body, dict)
                and body.get("status") == "healthy"
                and body.get("model_loaded") is True
                and body.get("expected_features") == 77
            ),
            str(body),
        )

        r, body = request_json(client, "GET", "/model-info")
        check(
            "GET /model-info returns the 77-feature contract",
            (
                r.status_code == 200
                and isinstance(body, dict)
                and body.get("feature_count") == 77
                and body.get("features") == feature_names
            ),
            f"status={r.status_code}",
        )

        # ------------------------------------------------------------------
        # Invalid prediction contract
        # ------------------------------------------------------------------

        incomplete = dict(benign_features)
        removed_feature = feature_names[-1]
        incomplete.pop(removed_feature)

        r, body = request_json(
            client,
            "POST",
            "/predict",
            json={
                "features": incomplete,
                "trigger_automation": False,
            },
        )

        missing_list = (
            body.get("detail", {}).get("missing_features", [])
            if isinstance(body, dict)
            else []
        )

        check(
            "Missing ML feature is rejected with HTTP 400",
            r.status_code == 400 and removed_feature in missing_list,
            f"status={r.status_code} removed={removed_feature}",
        )

        # ------------------------------------------------------------------
        # Genuine BENIGN through FastAPI, automation disabled
        # ------------------------------------------------------------------

        r, benign_result = request_json(
            client,
            "POST",
            "/predict",
            json={
                "features": benign_features,
                "metadata": {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "192.0.2.20",
                    "source_port": 51000,
                    "destination_port": 443,
                    "transport_protocol": "TCP",
                },
                "trigger_automation": False,
            },
        )

        benign_id = (
            benign_result.get("detection_id")
            if isinstance(benign_result, dict)
            else None
        )

        check(
            "Genuine BENIGN row returns HTTP 200",
            r.status_code == 200 and benign_id is not None,
            f"status={r.status_code} body={benign_result}",
        )

        check(
            "Genuine BENIGN row is classified BENIGN",
            (
                isinstance(benign_result, dict)
                and benign_result.get("prediction") == "BENIGN"
                and benign_result.get("attack") is False
            ),
            str(benign_result),
        )

        check(
            "BENIGN does not trigger automation",
            (
                isinstance(benign_result, dict)
                and benign_result.get("automation_triggered") is False
            ),
            f"automation_result={benign_result.get('automation_result') if isinstance(benign_result, dict) else None}",
        )

        # ------------------------------------------------------------------
        # Genuine ATTACK through FastAPI, automation explicitly disabled
        # ------------------------------------------------------------------

        r, attack_result = request_json(
            client,
            "POST",
            "/predict",
            json={
                "features": attack_features,
                "metadata": {
                    "source_ip": "198.51.100.10",
                    "destination_ip": "192.0.2.20",
                    "source_port": 52000,
                    "destination_port": 443,
                    "transport_protocol": "TCP",
                },
                "trigger_automation": False,
            },
        )

        attack_id = (
            attack_result.get("detection_id")
            if isinstance(attack_result, dict)
            else None
        )

        check(
            "Genuine DDoS row returns HTTP 200",
            r.status_code == 200 and attack_id is not None,
            f"status={r.status_code} body={attack_result}",
        )

        check(
            "Genuine DDoS row is classified ATTACK",
            (
                isinstance(attack_result, dict)
                and attack_result.get("prediction") == "ATTACK"
                and attack_result.get("attack") is True
            ),
            str(attack_result),
        )

        check(
            "ATTACK with trigger_automation=false does not call n8n",
            (
                isinstance(attack_result, dict)
                and attack_result.get("automation_triggered") is False
            ),
            f"automation_result={attack_result.get('automation_result') if isinstance(attack_result, dict) else None}",
        )

        # ------------------------------------------------------------------
        # Persistence validation
        # ------------------------------------------------------------------

        if benign_id is not None:
            r, body = request_json(
                client,
                "GET",
                f"/detections/{benign_id}",
            )

            check(
                "BENIGN detection persisted with network metadata",
                (
                    r.status_code == 200
                    and isinstance(body, dict)
                    and body.get("id") == benign_id
                    and body.get("prediction") == "BENIGN"
                    and body.get("source_ip") == "192.0.2.10"
                    and body.get("destination_port") == 443
                ),
                f"status={r.status_code} body={body}",
            )

            # BENIGN safety gates
            r, body = request_json(
                client,
                "POST",
                f"/detections/{benign_id}/enrichment",
                json={
                    "threat_provider": "Phase10-Test",
                    "threat_intelligence": {"test": True},
                },
            )
            check(
                "BENIGN threat enrichment is blocked",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

            r, body = request_json(
                client,
                "POST",
                f"/detections/{benign_id}/analysis",
            )
            check(
                "BENIGN LLM analysis is blocked",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

            r, body = request_json(
                client,
                "POST",
                f"/detections/{benign_id}/review",
                json={
                    "decision": "REJECT",
                    "action": None,
                    "note": "Phase 10 safety validation",
                },
            )
            check(
                "BENIGN human review is blocked",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

            r, body = request_json(
                client,
                "POST",
                f"/detections/{benign_id}/respond",
            )
            check(
                "BENIGN response execution is blocked",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

        # ------------------------------------------------------------------
        # ATTACK safety gates before enrichment/analysis/review
        # ------------------------------------------------------------------

        if attack_id is not None:
            r, body = request_json(
                client,
                "POST",
                f"/detections/{attack_id}/analysis",
            )
            check(
                "ATTACK cannot receive LLM analysis before threat intelligence",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

            r, body = request_json(
                client,
                "POST",
                f"/detections/{attack_id}/review",
                json={
                    "decision": "APPROVE",
                    "action": "LOG_ONLY",
                    "note": "Phase 10 premature-review test",
                },
            )
            check(
                "ATTACK cannot be reviewed before completed LLM analysis",
                r.status_code == 400,
                f"status={r.status_code} body={body}",
            )

            r, body = request_json(
                client,
                "POST",
                f"/detections/{attack_id}/respond",
            )
            check(
                "ATTACK response cannot execute before human approval",
                r.status_code == 403,
                f"status={r.status_code} body={body}",
            )

        # ------------------------------------------------------------------
        # Error/parameter contracts
        # ------------------------------------------------------------------

        r, body = request_json(
            client,
            "GET",
            "/detections/2147483647",
        )
        check(
            "Unknown detection ID returns 404",
            r.status_code == 404,
            f"status={r.status_code} body={body}",
        )

        r, body = request_json(
            client,
            "GET",
            "/dashboard/activity?hours=0",
        )
        check(
            "Invalid dashboard activity window returns 400",
            r.status_code == 400,
            f"status={r.status_code} body={body}",
        )

        r, body = request_json(
            client,
            "GET",
            "/dashboard/attention?limit=51",
        )
        check(
            "Invalid Analyst Queue limit returns 400",
            r.status_code == 400,
            f"status={r.status_code} body={body}",
        )

        # ------------------------------------------------------------------
        # Read-only operational endpoints
        # ------------------------------------------------------------------

        for path in (
            "/dashboard/stats",
            "/dashboard/activity",
            "/dashboard/severity",
            "/dashboard/top-ports",
            "/dashboard/top-sources",
            "/dashboard/attention",
            "/system/status",
        ):
            r, body = request_json(client, "GET", path)
            check(
                f"GET {path} returns 200",
                r.status_code == 200,
                f"status={r.status_code}",
            )

    print("\n" + "=" * 80)
    print("STEP 2 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nTwo controlled database rows were intentionally created "
            "(one BENIGN, one ATTACK)."
        )
        print(
            "n8n / AbuseIPDB / Gemini were NOT invoked because "
            "trigger_automation=false."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    sys.exit(main())
