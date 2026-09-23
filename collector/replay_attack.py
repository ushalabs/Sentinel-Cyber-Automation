import json
import math
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd


PREDICT_URL = "http://127.0.0.1:8000/predict"
DETECTION_URL = "http://127.0.0.1:8000/detections/{detection_id}"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEATURES_PATH = (
    PROJECT_ROOT
    / "ML Models"
    / "XGBoost"
    / "sentinel_feature_columns_v1.joblib"
)

# The chosen Parquet files intentionally contain no network metadata.
# These values are controlled metadata for the automation test only.
CONTROLLED_SOURCE_IP = "8.8.8.8"
CONTROLLED_DESTINATION_IP = "192.168.100.3"
CONTROLLED_SOURCE_PORT = 51515
CONTROLLED_DESTINATION_PORT = 443

POLL_INTERVAL_SECONDS = 2
POLL_TIMEOUT_SECONDS = 40


def normalize(name: str) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "",
        str(name).strip().lower(),
    )


ALIASES = {
    "Fwd Packets Length Total": [
        "Total Length of Fwd Packets",
        "Total Fwd Packet Length",
    ],
    "Bwd Packets Length Total": [
        "Total Length of Bwd Packets",
        "Total Bwd Packet Length",
    ],
    "Packet Length Min": ["Min Packet Length"],
    "Packet Length Max": ["Max Packet Length"],
    "Avg Packet Size": ["Average Packet Size"],
    "CWE Flag Count": [
        "CWR Flag Count",
        "CWE Flag Count",
    ],
    "Init Fwd Win Bytes": [
        "Init_Win_bytes_forward",
        "Init Win bytes forward",
    ],
    "Init Bwd Win Bytes": [
        "Init_Win_bytes_backward",
        "Init Win bytes backward",
    ],
    "Fwd Act Data Packets": [
        "act_data_pkt_fwd",
        "Active Data Packet Forward",
    ],
    "Fwd Seg Size Min": [
        "min_seg_size_forward",
        "Min Seg Size Forward",
    ],
}


def candidate_names(feature_name: str) -> list[str]:
    names = [feature_name]
    names.extend(ALIASES.get(feature_name, []))
    return [normalize(name) for name in names]


def find_column(normalized_headers, candidates):
    for candidate in candidates:
        if candidate in normalized_headers:
            return normalized_headers[candidate]
    return None


def infer_label_from_filename(path: Path) -> str:
    name = path.stem.lower()

    if "ddos" in name:
        return "DDoS"
    if "dos" in name:
        return "DoS"
    if "portscan" in name:
        return "PortScan"
    if "bruteforce" in name:
        return "BruteForce"
    if "botnet" in name:
        return "Botnet"
    if "infiltration" in name:
        return "Infiltration"
    if "webattacks" in name:
        return "WebAttack"

    return "ATTACK"


def request_json(url, method="GET", payload=None, timeout=30):
    body = None
    headers = {}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            return json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )
        raise RuntimeError(
            f"HTTP {exc.code}: {response_body}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not reach Sentinel service: {exc.reason}"
        ) from exc


def load_attack_features(parquet_path, expected_features):
    df = pd.read_parquet(parquet_path)

    if df.empty:
        raise RuntimeError(
            "The parquet file contains no rows."
        )

    normalized_headers = {
        normalize(column): column
        for column in df.columns
    }

    label_col = find_column(
        normalized_headers,
        ["label", "class", "attacklabel"],
    )

    feature_columns = {}
    missing = []

    for feature_name in expected_features:
        source_column = find_column(
            normalized_headers,
            candidate_names(feature_name),
        )

        if source_column is None:
            missing.append(feature_name)
        else:
            feature_columns[feature_name] = source_column

    if missing:
        print("\nMissing model columns:")
        for feature in missing:
            print(f"  - {feature}")

        raise RuntimeError(
            "This parquet does not match Sentinel's 77-feature contract."
        )

    dataset_label = infer_label_from_filename(parquet_path)
    skipped = 0

    for index, row in df.iterrows():
        if label_col is not None:
            label = str(row[label_col]).strip()

            if label.upper() in {
                "BENIGN",
                "NORMAL",
                "0",
            }:
                continue

            dataset_label = label

        try:
            features = {}

            for feature_name, source_column in feature_columns.items():
                value = float(row[source_column])

                if not math.isfinite(value):
                    raise ValueError

                features[feature_name] = value

        except (ValueError, TypeError):
            skipped += 1
            continue

        return index, dataset_label, features, skipped

    raise RuntimeError(
        "No finite ATTACK row was found."
    )


def poll_incident(detection_id):
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    last_incident = None

    while time.time() < deadline:
        incident = request_json(
            DETECTION_URL.format(
                detection_id=detection_id
            )
        )

        last_incident = incident

        status = incident.get(
            "analysis_status"
        )

        if status in {
            "COMPLETED",
            "FAILED",
        }:
            return incident

        time.sleep(
            POLL_INTERVAL_SECONDS
        )

    return last_incident


def main():
    print("=" * 74)
    print(
        "Sentinel Step 26B - Genuine ATTACK -> n8n -> Threat Intel -> Gemini"
    )
    print("=" * 74)
    print("Automation : ENABLED")
    print(
        "ML features: genuine CIC-IDS2017 ATTACK row"
    )
    print(
        "Metadata   : CONTROLLED test metadata (not from the dataset)"
    )
    print("=" * 74)

    if not FEATURES_PATH.exists():
        raise FileNotFoundError(
            f"Feature contract not found: {FEATURES_PATH}"
        )

    expected_features = list(
        joblib.load(FEATURES_PATH)
    )

    if len(expected_features) != 77:
        raise RuntimeError(
            f"Expected 77 saved features, "
            f"found {len(expected_features)}."
        )

    parquet_text = input(
        "\nPaste the full path to ONE ATTACK .parquet file: "
    ).strip().strip('"')

    parquet_path = Path(
        parquet_text
    )

    if not parquet_path.exists():
        raise FileNotFoundError(
            f"File not found: {parquet_path}"
        )

    print(
        f"\nLoading: {parquet_path.name}"
    )

    (
        row_index,
        dataset_label,
        features,
        skipped,
    ) = load_attack_features(
        parquet_path,
        expected_features,
    )

    protocol_number = int(
        features.get("Protocol", 0)
    )

    protocol_name = {
        6: "TCP",
        17: "UDP",
    }.get(
        protocol_number,
        str(protocol_number),
    )

    metadata = {
        "source_ip": CONTROLLED_SOURCE_IP,
        "destination_ip": CONTROLLED_DESTINATION_IP,
        "source_port": CONTROLLED_SOURCE_PORT,
        "destination_port": CONTROLLED_DESTINATION_PORT,
        "transport_protocol": protocol_name,
        "observed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    print()
    print("-" * 74)
    print("CONTROLLED ATTACK REPLAY READY")
    print("-" * 74)
    print(
        f"Dataset label         : {dataset_label}"
    )
    print(
        f"Parquet row index     : {row_index}"
    )
    print(
        "Feature contract      : 77/77"
    )
    print(
        f"Skipped invalid rows  : {skipped}"
    )
    print(
        f"Controlled source IP  : {CONTROLLED_SOURCE_IP}"
    )
    print(
        f"Controlled dest IP    : {CONTROLLED_DESTINATION_IP}"
    )
    print(
        "n8n automation        : ENABLED"
    )

    print(
        "\nSending ATTACK replay to /predict..."
    )

    prediction = request_json(
        PREDICT_URL,
        method="POST",
        payload={
            "features": features,
            "metadata": metadata,
            "trigger_automation": True,
        },
    )

    print()
    print("=" * 74)
    print("XGBOOST RESULT")
    print("=" * 74)

    print(
        f"Prediction            : "
        f"{prediction.get('prediction')}"
    )
    print(
        f"Confidence            : "
        f"{prediction.get('confidence')}"
    )
    print(
        f"Attack probability    : "
        f"{prediction.get('attack_probability')}"
    )
    print(
        f"Detection ID          : "
        f"{prediction.get('detection_id')}"
    )
    print(
        f"Automation triggered  : "
        f"{prediction.get('automation_triggered')}"
    )

    if (
        prediction.get("prediction")
        != "ATTACK"
    ):
        print()
        print(
            "STOP: replay was not classified as ATTACK."
        )
        return

    detection_id = prediction.get(
        "detection_id"
    )

    if not prediction.get(
        "automation_triggered"
    ):
        print()
        print(
            "STOP: FastAPI did not trigger n8n."
        )
        print(
            f"Automation result: "
            f"{prediction.get('automation_result')}"
        )
        return

    print()
    print(
        "Waiting for enrichment + Gemini analysis..."
    )

    incident = poll_incident(
        detection_id
    )

    if not incident:
        print(
            "Could not retrieve the incident."
        )
        return

    analysis = (
        incident.get(
            "incident_analysis"
        )
        or {}
    )

    print()
    print("=" * 74)
    print("AUTOMATION PIPELINE RESULT")
    print("=" * 74)

    print(
        f"Detection ID          : "
        f"{incident.get('id')}"
    )
    print(
        f"Threat provider       : "
        f"{incident.get('threat_provider')}"
    )
    print(
        f"Enriched              : "
        f"{incident.get('enriched_at') is not None}"
    )
    print(
        f"Analysis status       : "
        f"{incident.get('analysis_status')}"
    )
    print(
        f"LLM provider          : "
        f"{incident.get('llm_provider')}"
    )
    print(
        f"LLM model             : "
        f"{incident.get('llm_model')}"
    )
    print(
        f"Severity              : "
        f"{analysis.get('severity')}"
    )
    print(
        f"Review status         : "
        f"{incident.get('review_status')}"
    )

    if (
        incident.get(
            "analysis_status"
        )
        == "COMPLETED"
        and incident.get(
            "threat_intelligence"
        )
        is not None
    ):
        print()
        print(
            "RESULT: PASS - genuine ATTACK features reached "
            "XGBoost -> n8n -> threat intelligence -> Gemini."
        )
        print(
            "Human review remains intentionally manual."
        )
    else:
        print()
        print(
            "RESULT: INVESTIGATE - the automation chain "
            "did not fully complete."
        )
        print(
            f"Analysis error        : "
            f"{incident.get('analysis_error')}"
        )


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\nReplay cancelled."
        )

    except Exception as exc:
        print()
        print(
            f"[Replay Error] {exc}"
        )
