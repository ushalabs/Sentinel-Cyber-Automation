from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import httpx
import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 20.0

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


def post_predict(payload: dict) -> tuple[int, dict | str]:
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.post(
            BASE_URL + "/predict",
            json=payload,
        )

        try:
            body = response.json()
        except Exception:
            body = response.text

        return response.status_code, body


def count_request_id(request_id: str) -> int | None:
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.get(
            BASE_URL + "/detections?limit=50"
        )

        if response.status_code != 200:
            return None

        rows = response.json()

        return sum(
            1
            for row in rows
            if row.get("request_id") == request_id
        )


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 9B")
    print("IDEMPOTENCY / RETRY / CONCURRENCY VALIDATION")
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

    with httpx.Client(timeout=TIMEOUT) as client:
        system_response = client.get(
            BASE_URL + "/system/status"
        )
        system = system_response.json()

    check(
        "System preflight succeeds",
        (
            system_response.status_code == 200
            and system.get("api") == "ONLINE"
            and system.get("database") == "ONLINE"
            and system.get("model") == "LOADED"
        ),
        str(system),
    )

    retry_id = "phase10-" + uuid4().hex

    payload = {
        "request_id": retry_id,
        "features": benign_features,
        "metadata": {
            "source_ip": "192.0.2.210",
            "destination_ip": "192.0.2.211",
            "source_port": 62000,
            "destination_port": 443,
            "transport_protocol": "TCP",
        },
        "trigger_automation": False,
    }

    first_status, first = post_predict(payload)
    second_status, second = post_predict(payload)

    check(
        "First request creates a normal detection",
        (
            first_status == 200
            and isinstance(first, dict)
            and first.get("prediction") == "BENIGN"
            and first.get("request_id") == retry_id
            and first.get("idempotent_replay") is False
        ),
        f"status={first_status} body={first}",
    )

    check(
        "Exact retry returns HTTP 200",
        second_status == 200,
        f"status={second_status} body={second}",
    )

    first_id = first.get("detection_id") if isinstance(first, dict) else None
    second_id = second.get("detection_id") if isinstance(second, dict) else None

    check(
        "Exact retry resolves to the SAME detection ID",
        first_id is not None and first_id == second_id,
        f"first_id={first_id} second_id={second_id}",
    )

    check(
        "Retry is explicitly marked idempotent and automation is skipped",
        (
            isinstance(second, dict)
            and second.get("idempotent_replay") is True
            and second.get("automation_triggered") is False
            and isinstance(second.get("automation_result"), dict)
            and second["automation_result"].get("status") == "skipped"
        ),
        str(second),
    )

    sequential_count = count_request_id(retry_id)

    check(
        "Sequential retry creates exactly ONE database row",
        sequential_count == 1,
        f"request_id={retry_id} rows={sequential_count}",
    )

    conflicting_payload = {
        **payload,
        "metadata": {
            **payload["metadata"],
            "source_port": 62001,
        },
    }

    conflict_status, conflict = post_predict(
        conflicting_payload
    )

    check(
        "Reusing request_id for a different payload is rejected with HTTP 409",
        conflict_status == 409,
        f"status={conflict_status} body={conflict}",
    )

    conflict_count = count_request_id(retry_id)

    check(
        "Conflict attempt does not create another database row",
        conflict_count == 1,
        f"request_id={retry_id} rows={conflict_count}",
    )

    concurrent_id = "phase10-" + uuid4().hex

    concurrent_payload = {
        "request_id": concurrent_id,
        "features": benign_features,
        "metadata": {
            "source_ip": "192.0.2.220",
            "destination_ip": "192.0.2.221",
            "source_port": 63000,
            "destination_port": 443,
            "transport_protocol": "TCP",
        },
        "trigger_automation": False,
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                post_predict,
                concurrent_payload,
            )
            for _ in range(2)
        ]

        concurrent_results = [
            future.result()
            for future in futures
        ]

    statuses = [
        status
        for status, _ in concurrent_results
    ]

    bodies = [
        body
        for _, body in concurrent_results
    ]

    concurrent_detection_ids = {
        body.get("detection_id")
        for body in bodies
        if isinstance(body, dict)
        and body.get("detection_id") is not None
    }

    check(
        "Both concurrent duplicate requests return HTTP 200",
        statuses == [200, 200],
        f"statuses={statuses} bodies={bodies}",
    )

    check(
        "Concurrent duplicates resolve to ONE detection ID",
        len(concurrent_detection_ids) == 1,
        f"detection_ids={concurrent_detection_ids}",
    )

    replay_flags = [
        body.get("idempotent_replay")
        for body in bodies
        if isinstance(body, dict)
    ]

    check(
        "Concurrent pair contains one new result and one replay result",
        sorted(replay_flags) == [False, True],
        f"idempotent_replay={replay_flags}",
    )

    concurrent_count = count_request_id(
        concurrent_id
    )

    check(
        "Concurrent duplicate race creates exactly ONE database row",
        concurrent_count == 1,
        f"request_id={concurrent_id} rows={concurrent_count}",
    )

    print("\n" + "=" * 80)
    print("STEP 9B RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel is idempotent for explicit request_id retries: "
            "sequential retries return the existing detection, request_id "
            "collisions with changed payloads are rejected, and concurrent "
            "duplicates are collapsed to one database row."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
