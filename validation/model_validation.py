from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb


ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = ROOT / "Dataset" / "CIC-IDS2017"
MODEL_PATH = ROOT / "ML Models" / "XGBoost" / "sentinel_xgboost_binary_v1.json"
FEATURES_PATH = ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"

RESULTS_DIR = ROOT / "validation" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
THRESHOLD = 0.50

# Up to this many rows of EACH real class are sampled from each parquet file.
# Example: a mixed DDoS-day parquet may contribute up to 250 BENIGN + 250 ATTACK.
SAMPLES_PER_CLASS_PER_FILE = 250

DATASET_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]

LABEL_CANDIDATES = [
    "Label",
    "label",
    "LABEL",
    "Class",
    "class",
    "Target",
    "target",
]


def find_label_column(df: pd.DataFrame) -> str:
    for candidate in LABEL_CANDIDATES:
        if candidate in df.columns:
            return candidate

    # Last-resort normalized search.
    normalized = {str(c).strip().lower(): c for c in df.columns}
    for key in ("label", "class", "target"):
        if key in normalized:
            return normalized[key]

    raise RuntimeError(
        "Could not find the dataset label column. "
        f"Available columns include: {list(df.columns)[:20]}"
    )


def label_to_binary(value) -> int:
    """
    CIC-IDS2017 binary convention:
      BENIGN -> 0
      every attack family -> 1
    """
    if pd.isna(value):
        raise ValueError("Missing label")

    if isinstance(value, (bool, np.bool_)):
        return int(value)

    if isinstance(value, (int, np.integer)):
        if int(value) in (0, 1):
            return int(value)

    if isinstance(value, (float, np.floating)) and np.isfinite(value):
        if float(value) in (0.0, 1.0):
            return int(value)

    text = str(value).strip().upper()

    if text in {"0", "0.0", "BENIGN", "NORMAL"}:
        return 0

    # Anything else is an attack family such as DDoS, DoS Hulk,
    # PortScan, Bot, Web Attack, Infiltration, etc.
    return 1


def load_feature_names() -> list[str]:
    names = list(joblib.load(FEATURES_PATH))
    if len(names) != 77:
        raise RuntimeError(
            f"Feature contract mismatch: expected 77 features, found {len(names)}."
        )
    return names


def load_model() -> xgb.Booster:
    booster = xgb.Booster()
    booster.load_model(str(MODEL_PATH))
    return booster


def confusion(expected: np.ndarray, predicted: np.ndarray) -> dict[str, int]:
    return {
        "tn": int(np.sum((expected == 0) & (predicted == 0))),
        "fp": int(np.sum((expected == 0) & (predicted == 1))),
        "fn": int(np.sum((expected == 1) & (predicted == 0))),
        "tp": int(np.sum((expected == 1) & (predicted == 1))),
    }


def safe_rate(num: int, denom: int) -> float | None:
    return (num / denom) if denom else None


def main() -> None:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 1B")
    print("CORRECTED LABEL-AWARE MULTI-DATASET XGBOOST VALIDATION")
    print("=" * 80)

    feature_names = load_feature_names()
    booster = load_model()

    print(f"\nModel         : {MODEL_PATH.name}")
    print(f"Feature file  : {FEATURES_PATH.name}")
    print(f"Feature count : {len(feature_names)}/77")
    print(f"Threshold     : {THRESHOLD}")
    print(
        "Sampling      : up to "
        f"{SAMPLES_PER_CLASS_PER_FILE} rows PER TRUE CLASS per parquet"
    )

    summaries = []
    prediction_rows = []
    all_expected = []
    all_predicted = []

    for filename in DATASET_FILES:
        path = DATASET_DIR / filename

        print("\n" + "-" * 80)
        print(filename)
        print("-" * 80)

        if not path.exists():
            print("STATUS         : MISSING")
            summaries.append({"dataset": filename, "status": "MISSING"})
            continue

        df = pd.read_parquet(path)
        label_col = find_label_column(df)

        missing_features = [f for f in feature_names if f not in df.columns]
        if missing_features:
            raise RuntimeError(
                f"{filename} is missing production features:\n- "
                + "\n- ".join(missing_features)
            )

        # Convert the dataset's real label column to the binary production target.
        labels = df[label_col].map(label_to_binary)

        features = df.loc[:, feature_names].apply(pd.to_numeric, errors="coerce")
        values = features.to_numpy(dtype=np.float64, copy=False)
        finite_mask = np.isfinite(values).all(axis=1)

        valid = features.loc[finite_mask].copy()
        valid["__expected_class__"] = labels.loc[finite_mask].astype(np.int32).values
        valid["__original_label__"] = (
            df.loc[finite_mask, label_col].astype(str).values
        )

        class_counts = valid["__expected_class__"].value_counts().to_dict()
        benign_available = int(class_counts.get(0, 0))
        attack_available = int(class_counts.get(1, 0))

        parts = []
        for true_class in (0, 1):
            class_rows = valid[valid["__expected_class__"] == true_class]
            if class_rows.empty:
                continue

            n = min(SAMPLES_PER_CLASS_PER_FILE, len(class_rows))
            parts.append(
                class_rows.sample(
                    n=n,
                    random_state=RANDOM_STATE + true_class,
                    replace=False,
                )
            )

        if not parts:
            print("STATUS         : NO VALID LABELED FINITE ROWS")
            summaries.append(
                {
                    "dataset": filename,
                    "status": "NO_VALID_ROWS",
                    "label_column": label_col,
                }
            )
            continue

        sample = pd.concat(parts, ignore_index=True)

        expected = sample["__expected_class__"].to_numpy(dtype=np.int32)
        original_labels = sample["__original_label__"].tolist()
        model_input = sample.loc[:, feature_names]

        dmatrix = xgb.DMatrix(model_input, feature_names=feature_names)
        attack_probability = booster.predict(dmatrix)
        predicted = (attack_probability >= THRESHOLD).astype(np.int32)

        correct_mask = predicted == expected
        counts = confusion(expected, predicted)

        accuracy = float(correct_mask.mean())
        precision = safe_rate(counts["tp"], counts["tp"] + counts["fp"])
        recall = safe_rate(counts["tp"], counts["tp"] + counts["fn"])
        specificity = safe_rate(counts["tn"], counts["tn"] + counts["fp"])

        all_expected.extend(expected.tolist())
        all_predicted.extend(predicted.tolist())

        summaries.append(
            {
                "dataset": filename,
                "status": "OK",
                "label_column": label_col,
                "finite_benign_available": benign_available,
                "finite_attack_available": attack_available,
                "rows_tested": int(len(sample)),
                "benign_tested": int(np.sum(expected == 0)),
                "attack_tested": int(np.sum(expected == 1)),
                "correct": int(correct_mask.sum()),
                "incorrect": int((~correct_mask).sum()),
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "specificity": specificity,
                **counts,
            }
        )

        for i in range(len(sample)):
            prediction_rows.append(
                {
                    "dataset": filename,
                    "sample_index": i,
                    "original_label": original_labels[i],
                    "expected_class": int(expected[i]),
                    "predicted_class": int(predicted[i]),
                    "attack_probability": float(attack_probability[i]),
                    "correct": bool(correct_mask[i]),
                }
            )

        print(f"Label column   : {label_col}")
        print(f"Finite BENIGN  : {benign_available:,}")
        print(f"Finite ATTACK  : {attack_available:,}")
        print(f"Rows tested    : {len(sample):,}")
        print(f"  BENIGN       : {int(np.sum(expected == 0)):,}")
        print(f"  ATTACK       : {int(np.sum(expected == 1)):,}")
        print(f"Correct        : {int(correct_mask.sum()):,}")
        print(f"Incorrect      : {int((~correct_mask).sum()):,}")
        print(f"Accuracy       : {accuracy * 100:.2f}%")
        if precision is not None:
            print(f"Precision      : {precision * 100:.2f}%")
        if recall is not None:
            print(f"Recall         : {recall * 100:.2f}%")
        if specificity is not None:
            print(f"Specificity    : {specificity * 100:.2f}%")
        print(
            f"Confusion      : TN={counts['tn']} FP={counts['fp']} "
            f"FN={counts['fn']} TP={counts['tp']}"
        )

    if not all_expected:
        raise RuntimeError("No validation rows were processed.")

    expected_np = np.asarray(all_expected, dtype=np.int32)
    predicted_np = np.asarray(all_predicted, dtype=np.int32)
    overall = confusion(expected_np, predicted_np)

    total = len(expected_np)
    correct = int(np.sum(expected_np == predicted_np))
    accuracy = correct / total
    precision = safe_rate(overall["tp"], overall["tp"] + overall["fp"])
    recall = safe_rate(overall["tp"], overall["tp"] + overall["fn"])
    specificity = safe_rate(overall["tn"], overall["tn"] + overall["fp"])

    print("\n" + "=" * 80)
    print("OVERALL LABEL-AWARE RESULT")
    print("=" * 80)
    print(f"Rows tested    : {total:,}")
    print(f"BENIGN tested  : {int(np.sum(expected_np == 0)):,}")
    print(f"ATTACK tested  : {int(np.sum(expected_np == 1)):,}")
    print(f"Correct        : {correct:,}")
    print(f"Incorrect      : {total - correct:,}")
    print(f"Accuracy       : {accuracy * 100:.2f}%")
    if precision is not None:
        print(f"Precision      : {precision * 100:.2f}%")
    if recall is not None:
        print(f"Recall         : {recall * 100:.2f}%")
    if specificity is not None:
        print(f"Specificity    : {specificity * 100:.2f}%")
    print(
        f"Confusion      : TN={overall['tn']} FP={overall['fp']} "
        f"FN={overall['fn']} TP={overall['tp']}"
    )

    summary_csv = RESULTS_DIR / "phase10_step1b_label_aware_summary.csv"
    predictions_csv = RESULTS_DIR / "phase10_step1b_label_aware_predictions.csv"
    report_json = RESULTS_DIR / "phase10_step1b_label_aware_report.json"

    pd.DataFrame(summaries).to_csv(summary_csv, index=False)
    pd.DataFrame(prediction_rows).to_csv(predictions_csv, index=False)

    report = {
        "phase": 10,
        "step": "1B",
        "test": "label_aware_multi_dataset_xgboost_validation",
        "feature_count": len(feature_names),
        "threshold": THRESHOLD,
        "samples_per_class_per_file": SAMPLES_PER_CLASS_PER_FILE,
        "overall": {
            "rows_tested": total,
            "benign_tested": int(np.sum(expected_np == 0)),
            "attack_tested": int(np.sum(expected_np == 1)),
            "correct": correct,
            "incorrect": total - correct,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            **overall,
        },
        "datasets": summaries,
    }

    report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nReports saved:")
    print(f"  {summary_csv}")
    print(f"  {predictions_csv}")
    print(f"  {report_json}")

    print("\nIMPORTANT:")
    print("- Expected labels came from the Parquet label column, NOT the filename.")
    print("- CIC-IDS2017 attack-day files can contain large amounts of BENIGN traffic.")
    print("- This is the valid Step 1 model-regression result.")


if __name__ == "__main__":
    main()
