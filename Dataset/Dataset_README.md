# CIC-IDS2017 Dataset

Sentinel uses the **CIC-IDS2017 (Intrusion Detection Evaluation Dataset)** published by the Canadian Institute for Cybersecurity (CIC), University of New Brunswick.

The raw dataset is intentionally **not stored in this Git repository** because of its size. The local Sentinel project uses a compressed archive of roughly **232 MB**, while the full dataset is substantially larger.

## Official Dataset Page

Download CIC-IDS2017 from the official University of New Brunswick / Canadian Institute for Cybersecurity page:

**https://www.unb.ca/cic/datasets/ids-2017.html**

For Sentinel's machine-learning pipeline, use the labeled flow / CSV data provided for machine-learning purposes.

The official page describes CIC-IDS2017 as containing benign traffic and multiple common attack families, with labeled network flows generated using CICFlowMeter.

## Dataset Used by Sentinel

Sentinel Phase 1 used CIC-IDS2017 for binary intrusion detection:

```text
BENIGN â†’ 0
ATTACK â†’ 1
```

The original attack classes were collapsed into the single `ATTACK` class.

After Sentinel's preprocessing pipeline, the production feature contract contains **77 numeric input features**.

The exact feature ordering used by the trained models is stored in:

```text
ML Models/*/sentinel_feature_columns_v1.joblib
```

## Local Placement

After downloading the dataset, keep it locally under:

```text
Sentinel/
â””â”€â”€ Dataset/
    â””â”€â”€ CIC-IDS2017.zip
```

The archive itself is excluded from Git.

## Reproducing the ML Pipeline

The model-training notebooks are available under:

```text
ML Models/
â”œâ”€â”€ Random Forest/
â”œâ”€â”€ XGBoost/
â”œâ”€â”€ KNN/
â””â”€â”€ CNN/
```

Use those notebooks as the source of truth for:

- dataset loading
- preprocessing
- binary-label conversion
- train/test splitting
- feature scaling where required
- model training
- evaluation
- artifact export

## Citation

If you use CIC-IDS2017 in research or another project, cite the dataset paper listed on the official CIC dataset page:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani,
â€œToward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,â€
4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.

---

**Note:** The dataset is excluded from this repository only to keep the Git history lightweight and reproducible. It can be downloaded again from the official source above.
