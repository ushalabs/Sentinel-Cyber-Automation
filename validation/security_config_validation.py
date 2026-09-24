from __future__ import annotations

from pathlib import Path

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 15.0

FEATURES_PATH = (
    ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
)

BENIGN_DATASET = (
    ROOT / "Dataset" / "CIC-IDS2017" / "Benign-Monday-no-metadata.parquet"
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

    candidates = features.loc[finite_mask & (labels == 0)]

    if candidates.empty:
        raise RuntimeError("No finite BENIGN row found.")

    row = candidates.iloc[0]

    return {name: float(row[name]) for name in feature_names}


def contains_sensitive_name(value) -> bool:
    text = str(value).upper()
    sensitive_names = (
        "GEMINI_API_KEY",
        "DB_PASSWORD",
        "N8N_WEBHOOK_URL",
        "ABUSEIPDB_API_KEY",
    )
    return any(name in text for name in sensitive_names)


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 10")
    print("SECURITY / CONFIGURATION CLEANUP VALIDATION")
    print("=" * 80)

    feature_names = list(joblib.load(FEATURES_PATH))
    benign_features = load_genuine_benign_row(
        BENIGN_DATASET,
        feature_names,
    )

    with httpx.Client(timeout=TIMEOUT) as client:
        # --------------------------------------------------------------
        # Service/config baseline
        # --------------------------------------------------------------
        root_response = client.get(BASE_URL + "/")
        root = root_response.json()

        check(
            "Root endpoint reports Phase 10",
            root_response.status_code == 200
            and root.get("phase") == 10,
            str(root),
        )

        status_response = client.get(BASE_URL + "/system/status")
        status = status_response.json()

        check(
            "Core API/database/model are healthy",
            (
                status_response.status_code == 200
                and status.get("api") == "ONLINE"
                and status.get("database") == "ONLINE"
                and status.get("model") == "LOADED"
            ),
            str(status),
        )

        # --------------------------------------------------------------
        # Secret/config exposure checks
        # --------------------------------------------------------------
        public_payloads = []

        for endpoint in ("/", "/health", "/model-info"):
            response = client.get(BASE_URL + endpoint)
            public_payloads.append(response.text)

        exposed = any(
            contains_sensitive_name(payload)
            for payload in public_payloads
        )

        check(
            "Public metadata endpoints do not expose secret variable names",
            not exposed,
        )

        root_gitignore = ROOT / ".gitignore"
        backend_gitignore = ROOT / "backend" / ".gitignore"

        root_ignore_text = (
            root_gitignore.read_text(encoding="utf-8")
            if root_gitignore.exists()
            else ""
        )

        backend_ignore_text = (
            backend_gitignore.read_text(encoding="utf-8")
            if backend_gitignore.exists()
            else ""
        )

        env_ignored = (
            "backend/.env" in root_ignore_text
            or ".env" in backend_ignore_text
        )

        check(
            "backend/.env is ignored by Git configuration",
            env_ignored,
            (
                f"root .gitignore exists={root_gitignore.exists()} "
                f"backend .gitignore exists={backend_gitignore.exists()}"
            ),
        )

        # --------------------------------------------------------------
        # CORS boundary
        # --------------------------------------------------------------
        allowed_preflight = client.options(
            BASE_URL + "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        allowed_origin = allowed_preflight.headers.get(
            "access-control-allow-origin"
        )

        check(
            "Configured dashboard origin is allowed by CORS",
            (
                allowed_preflight.status_code in (200, 204)
                and allowed_origin == "http://localhost:3000"
            ),
            (
                f"status={allowed_preflight.status_code} "
                f"allow-origin={allowed_origin}"
            ),
        )

        denied_preflight = client.options(
            BASE_URL + "/health",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )

        denied_origin = denied_preflight.headers.get(
            "access-control-allow-origin"
        )

        check(
            "Unapproved browser origin is not granted CORS access",
            denied_origin != "https://evil.example",
            (
                f"status={denied_preflight.status_code} "
                f"allow-origin={denied_origin}"
            ),
        )

        # --------------------------------------------------------------
        # Review action allowlist validation
        # Pydantic should reject this before detection lookup.
        # --------------------------------------------------------------
        invalid_review = client.post(
            BASE_URL + "/detections/999999999/review",
            json={
                "decision": "APPROVE",
                "action": "DELETE_SYSTEM",
                "note": "Phase 10 invalid-action validation",
            },
        )

        check(
            "Unsupported response action is rejected at request validation",
            invalid_review.status_code == 422,
            (
                f"status={invalid_review.status_code} "
                f"body={invalid_review.text}"
            ),
        )

        # --------------------------------------------------------------
        # request_id input validation
        # --------------------------------------------------------------
        too_long_request_id = "x" * 65

        bad_id_response = client.post(
            BASE_URL + "/predict",
            json={
                "request_id": too_long_request_id,
                "features": benign_features,
                "trigger_automation": False,
            },
        )

        check(
            "request_id longer than 64 characters is rejected",
            bad_id_response.status_code == 422,
            (
                f"status={bad_id_response.status_code} "
                f"body={bad_id_response.text}"
            ),
        )

        # --------------------------------------------------------------
        # Feature-contract validation still enforced
        # --------------------------------------------------------------
        incomplete_features = dict(benign_features)
        removed_feature = feature_names[-1]
        incomplete_features.pop(removed_feature)

        missing_feature_response = client.post(
            BASE_URL + "/predict",
            json={
                "features": incomplete_features,
                "trigger_automation": False,
            },
        )

        try:
            missing_body = missing_feature_response.json()
        except Exception:
            missing_body = missing_feature_response.text

        check(
            "Missing production feature is rejected with HTTP 400",
            missing_feature_response.status_code == 400,
            (
                f"removed={removed_feature} "
                f"status={missing_feature_response.status_code} "
                f"body={missing_body}"
            ),
        )

        # --------------------------------------------------------------
        # BENIGN cannot trigger automation even when requested.
        # This creates one controlled BENIGN validation record.
        # --------------------------------------------------------------
        benign_response = client.post(
            BASE_URL + "/predict",
            json={
                "features": benign_features,
                "metadata": {
                    "source_ip": "192.0.2.240",
                    "destination_ip": "192.0.2.241",
                    "source_port": 64000,
                    "destination_port": 443,
                    "transport_protocol": "TCP",
                },
                "trigger_automation": True,
            },
        )

        benign_body = benign_response.json()

        check(
            "BENIGN prediction cannot trigger n8n automation",
            (
                benign_response.status_code == 200
                and benign_body.get("prediction") == "BENIGN"
                and benign_body.get("automation_triggered") is False
                and isinstance(
                    benign_body.get("automation_result"),
                    dict,
                )
                and benign_body["automation_result"].get("reason")
                == "BENIGN detection"
            ),
            str(benign_body),
        )

    print("\n" + "=" * 80)
    print("STEP 10 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel's current configuration boundaries passed: "
            "Phase 10 status is exposed correctly, public metadata does not "
            "surface secret variable names, .env is ignored, CORS is restricted "
            "to the dashboard origins, unsupported response actions are rejected "
            "during request validation, request IDs are bounded, the 77-feature "
            "contract remains enforced, and BENIGN traffic cannot trigger automation."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
