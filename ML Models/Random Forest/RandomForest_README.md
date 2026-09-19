# Random Forest Model Artifact

This folder contains the notebook and supporting artifacts used to train Sentinel's **Random Forest** binary intrusion-detection model.

---

## Files Included in Git

The following files should remain in the repository:

```text
01_CICIDS2017_RandomForest.ipynb
sentinel_feature_columns_v1.joblib
README.md
```

---

## Large Binary Excluded

The trained Random Forest model:

```text
sentinel_random_forest_binary_v1.joblib
```

is intentionally excluded from normal Git tracking.

Its local size is approximately:

```text
50.44 MB
```

Although this is below GitHub's hard 100 MB single-file limit, generated binaries of this size unnecessarily increase repository size and Git history.

The model is reproducible from the training notebook, so the repository keeps the source notebook rather than the generated binary.

The root `.gitignore` should contain:

```gitignore
ML Models/Random Forest/sentinel_random_forest_binary_v1.joblib
```

---

## How to Recreate the Random Forest Model

### 1. Download CIC-IDS2017

Sentinel uses the CIC-IDS2017 dataset.

Official dataset page:

**https://www.unb.ca/cic/datasets/ids-2017.html**

Dataset setup instructions are also available in:

```text
Sentinel/Dataset/Dataset_README.md
```

---

## 2. Open the Training Notebook

Open:

```text
01_CICIDS2017_RandomForest.ipynb
```

The notebook was developed as part of Sentinel Phase 1 and can be run in Google Colab or another compatible Jupyter environment.

---

## 3. Provide the Dataset

Make the CIC-IDS2017 data available to the notebook.

If your local / Colab paths differ from the original environment, update the dataset path variables before running the notebook.

---

## 4. Run the Pipeline

Run the notebook cells in order.

The training pipeline conceptually performs:

```text
CIC-IDS2017
      â†“
Cleaning / preprocessing
      â†“
Binary Label Conversion
BENIGN = 0
ATTACK = 1
      â†“
77-Feature Schema
      â†“
Stratified Train/Test Split
      â†“
Random Forest Training
      â†“
Evaluation
      â†“
Artifact Export
```

Random Forest does not require the same external feature scaler used by KNN or CNN.

---

## 5. Expected Output Artifact

The recreated model should be saved as:

```text
sentinel_random_forest_binary_v1.joblib
```

Place it in:

```text
Sentinel/
â””â”€â”€ ML Models/
    â””â”€â”€ Random Forest/
        â””â”€â”€ sentinel_random_forest_binary_v1.joblib
```

This file will remain local because it is ignored by Git.

---

## Feature Contract

The Random Forest model must use the same 77-feature schema used during training.

The feature contract is stored in:

```text
sentinel_feature_columns_v1.joblib
```

The model and feature-column file must remain synchronized.

Do not replace the feature list with one generated from a different preprocessing pipeline unless the feature order is known to be identical.

---

## Known Phase 1 Performance

The Random Forest model produced strong held-out test results during Phase 1.

Recorded results included approximately:

```text
Accuracy:          0.998862
Attack Precision:  0.997334
Attack Recall:     0.995111
Attack F1:         0.996222
False Positives:   179
False Negatives:   329
True Positives:    66,970
True Negatives:    378,884
Training Time:     ~805.28 seconds
```

Random Forest remains useful as a comparison model even though Sentinel currently uses XGBoost as the primary production inference model.

---

## Why XGBoost Is the Production Model

The production Sentinel backend currently loads:

```text
ML Models/XGBoost/sentinel_xgboost_binary_v1.json
```

XGBoost was selected as the initial production model because its held-out evaluation produced stronger attack recall and fewer missed attacks.

Therefore, excluding the Random Forest binary does **not** prevent the main Sentinel backend from running.

---

## Why This File Is Excluded

Keeping generated model binaries out of normal Git history helps the repository remain:

- lightweight
- fast to clone
- easier to review
- focused on source code and architecture
- reproducible from notebooks
- free from unnecessary binary history

If model artifact distribution is needed later, a dedicated release asset, artifact registry, cloud object storage, or Git LFS can be used instead.
