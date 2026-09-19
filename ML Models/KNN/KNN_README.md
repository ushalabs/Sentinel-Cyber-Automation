# KNN Model Artifact

This folder contains the notebook and supporting artifacts used to train Sentinel's **K-Nearest Neighbors (KNN)** binary intrusion-detection model.

## Files Included in Git

The following files should remain in the repository:

```text
03_CICIDS2017_KNN.ipynb
sentinel_feature_columns_v1.joblib
sentinel_knn_scaler_v1.joblib
```

## Large Model Artifact Excluded

The trained KNN model:

```text
sentinel_knn_binary_v1.joblib
```

is intentionally excluded from Git.

Its local size is approximately:

```text
1.08 GB
```

That is far too large for a normal GitHub repository and is reproducible from the training notebook.

The file should therefore be ignored with:

```gitignore
ML Models/KNN/sentinel_knn_binary_v1.joblib
```

## How to Recreate the KNN Model

The model can be regenerated from:

```text
03_CICIDS2017_KNN.ipynb
```

### 1. Download CIC-IDS2017

Official dataset page:

**https://www.unb.ca/cic/datasets/ids-2017.html**

Download the machine-learning CSV / labeled flow data required by the notebook.

### 2. Open the Notebook

The notebook was originally developed/trained using Google Colab.

Open:

```text
03_CICIDS2017_KNN.ipynb
```

in Google Colab or another compatible Jupyter environment.

### 3. Provide the Dataset

Upload/mount the CIC-IDS2017 dataset as expected by the notebook.

If paths differ from the original training environment, update only the dataset path variables before running the pipeline.

### 4. Run the Training Pipeline

Run the notebook cells in order.

The notebook performs the required pipeline, including:

```text
CIC-IDS2017
      â†“
Cleaning / preprocessing
      â†“
Binary labels
BENIGN = 0
ATTACK = 1
      â†“
77-feature schema
      â†“
Train / test split
      â†“
Feature scaling
      â†“
KNN training
      â†“
Evaluation
```

Because KNN is distance-based, the fitted scaler is required during inference.

### 5. Export the Artifacts

The resulting deployment files should include:

```text
sentinel_knn_binary_v1.joblib
sentinel_knn_scaler_v1.joblib
sentinel_feature_columns_v1.joblib
```

Place them in:

```text
Sentinel/
â””â”€â”€ ML Models/
    â””â”€â”€ KNN/
```

## Important

The following artifacts must stay synchronized:

```text
sentinel_knn_binary_v1.joblib
sentinel_knn_scaler_v1.joblib
sentinel_feature_columns_v1.joblib
```

Do not use a scaler or feature-column file generated from a different preprocessing run unless the pipeline is known to be identical.

The notebook is the source of truth for reproducing the model.

## Why the Binary Is Not Stored on GitHub

Excluding the 1+ GB binary keeps the repository:

- fast to clone
- easy to review
- within normal Git hosting limits
- reproducible from source
- focused on code and architecture rather than generated artifacts

Sentinel currently uses **XGBoost as its primary production inference model**, so the omitted KNN binary does not prevent the main backend from running.
