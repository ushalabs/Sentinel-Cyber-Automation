# Sentinel â€” Phase 1 Technical Record
## Binary Intrusion Detection Model Development

**Project:** Sentinel
**Phase:** 1 â€” ML Training & Evaluation
**Status:** âœ… Complete
**Completed:** September 2026

---

## 1. Objective

Phase 1 established Sentinel's machine-learning detection layer.

The goal was to prepare the CIC-IDS2017 network-traffic dataset, convert the original multiclass intrusion labels into a binary intrusion-detection task, train four different models, evaluate them on the same held-out test data, and save all artifacts required for later deployment.

The binary target used by Sentinel is:

- `0 = BENIGN`
- `1 = ATTACK`

The four models trained were:

1. Random Forest
2. XGBoost
3. K-Nearest Neighbors (KNN)
4. Convolutional Neural Network (CNN)

---

## 2. Dataset

**Dataset:** CIC-IDS2017

The source files were combined into a single working dataset before preprocessing.

### Dataset state

| Stage | Rows | Features / Columns |
|---|---:|---:|
| Combined raw dataset | 2,313,810 | 78 columns |
| Cleaned dataset | 2,231,806 | 77 numeric input features |

The original dataset contained multiple traffic labels covering benign traffic and multiple attack categories.

After cleaning and conversion to a binary target:

- **BENIGN:** 1,895,314 records (~84.92%)
- **ATTACK:** 336,492 records (~15.08%)

The cleaned feature set contained no remaining missing or invalid values before model training.

---

## 3. Preprocessing

The preprocessing pipeline performed the following major steps:

1. Loaded and combined the CIC-IDS2017 data.
2. Removed duplicate / unusable records.
3. Cleaned invalid numeric values.
4. Separated the target label from the traffic features.
5. Converted the original labels to a binary target:
   - Benign traffic â†’ `0`
   - Any attack category â†’ `1`
6. Preserved the final **77-feature input schema**.
7. Used a shared **stratified 80/20 train-test split** so class proportions remained consistent.
8. Applied feature scaling where required:
   - KNN â†’ scaled
   - CNN â†’ scaled
   - Random Forest â†’ no scaler required
   - XGBoost â†’ no external scaler required
9. Saved the final feature-column order so deployment would use the exact same input structure.

Approximate split size:

- **Training:** ~1,785,444 flows
- **Testing:** ~446,362 flows

---

## 4. Evaluation Strategy

All models were evaluated as binary intrusion detectors.

Important evaluation measures included:

- Accuracy
- Attack precision
- Attack recall
- F1 score
- Confusion matrix
- False positives
- False negatives
- Training time
- Inference behavior

For Sentinel, **attack recall and false negatives are especially important**, because a false negative represents malicious traffic being incorrectly classified as benign.

---

## 5. Models Trained

### 5.1 Random Forest

Random Forest was trained as the first binary baseline.

Known held-out test results:

| Metric | Result |
|---|---:|
| Accuracy | 0.998862 |
| Attack Precision | 0.997334 |
| Attack Recall | 0.995111 |
| Attack F1 | 0.996222 |
| True Negatives | 378,884 |
| False Positives | 179 |
| False Negatives | 329 |
| True Positives | 66,970 |
| Training Time | ~805.28 s |

Random Forest produced very few false positives and provided a strong baseline for the project.

---

### 5.2 XGBoost

XGBoost was trained on the same binary task and the same feature schema.

The training configuration included class-imbalance handling and a tree-boosting setup suitable for the large CIC-IDS2017 dataset.

Reported held-out performance was approximately:

- **Accuracy:** ~99.92%
- **Attack recall:** ~99.93%
- **Missed attacks / false negatives:** 48

XGBoost was selected as the **primary production candidate** because it achieved extremely high attack recall and missed substantially fewer attacks than the Random Forest baseline.

The final model was saved in native XGBoost JSON format.

---

### 5.3 K-Nearest Neighbors (KNN)

KNN was trained on the same 77-feature binary dataset.

Because KNN is distance-based, the input features were scaled before training and inference.

Deployment artifacts include both:

- the trained KNN model
- its fitted scaler

The model was evaluated on the full held-out test set and retained as one of Sentinel's comparison models.

---

### 5.4 Convolutional Neural Network (CNN)

A neural-network-based binary classifier was also trained to provide a deep-learning comparison against the classical ML models.

The CNN pipeline used scaled features and saved the best-performing trained model during training.

Deployment artifacts include:

- the best `.keras` model
- its fitted scaler
- the shared feature-column definition

The CNN remains available for model comparison and later experimentation.

---

## 6. Saved Artifacts

The final Phase 1 directory structure was:

```text
ML Models/
â”œâ”€â”€ CNN/
â”‚   â”œâ”€â”€ 04_CICIDS2017_CNN.ipynb
â”‚   â”œâ”€â”€ sentinel_cnn_binary_v1_best.keras
â”‚   â”œâ”€â”€ sentinel_cnn_scaler_v1.joblib
â”‚   â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚
â”œâ”€â”€ KNN/
â”‚   â”œâ”€â”€ 03_CICIDS2017_KNN.ipynb
â”‚   â”œâ”€â”€ sentinel_feature_columns_v1.joblib
â”‚   â”œâ”€â”€ sentinel_knn_binary_v1.joblib
â”‚   â””â”€â”€ sentinel_knn_scaler_v1.joblib
â”‚
â”œâ”€â”€ Random Forest/
â”‚   â”œâ”€â”€ 01_CICIDS2017_RandomForest.ipynb
â”‚   â”œâ”€â”€ sentinel_feature_columns_v1.joblib
â”‚   â””â”€â”€ sentinel_random_forest_binary_v1.joblib
â”‚
â””â”€â”€ XGBoost/
    â”œâ”€â”€ 02_CICIDS2017_XGBoost.ipynb
    â”œâ”€â”€ sentinel_feature_columns_v1.joblib
    â””â”€â”€ sentinel_xgboost_binary_v1.json
```

These files make the trained models reusable outside the original notebooks.

---

## 7. Final Feature Contract

All production inference must use the same **77 features** in the same training order.

The saved `sentinel_feature_columns_v1.joblib` file acts as the contract between model training and later deployment.

The feature order is:

1. Protocol
2. Flow Duration
3. Total Fwd Packets
4. Total Backward Packets
5. Fwd Packets Length Total
6. Bwd Packets Length Total
7. Fwd Packet Length Max
8. Fwd Packet Length Min
9. Fwd Packet Length Mean
10. Fwd Packet Length Std
11. Bwd Packet Length Max
12. Bwd Packet Length Min
13. Bwd Packet Length Mean
14. Bwd Packet Length Std
15. Flow Bytes/s
16. Flow Packets/s
17. Flow IAT Mean
18. Flow IAT Std
19. Flow IAT Max
20. Flow IAT Min
21. Fwd IAT Total
22. Fwd IAT Mean
23. Fwd IAT Std
24. Fwd IAT Max
25. Fwd IAT Min
26. Bwd IAT Total
27. Bwd IAT Mean
28. Bwd IAT Std
29. Bwd IAT Max
30. Bwd IAT Min
31. Fwd PSH Flags
32. Bwd PSH Flags
33. Fwd URG Flags
34. Bwd URG Flags
35. Fwd Header Length
36. Bwd Header Length
37. Fwd Packets/s
38. Bwd Packets/s
39. Packet Length Min
40. Packet Length Max
41. Packet Length Mean
42. Packet Length Std
43. Packet Length Variance
44. FIN Flag Count
45. SYN Flag Count
46. RST Flag Count
47. PSH Flag Count
48. ACK Flag Count
49. URG Flag Count
50. CWE Flag Count
51. ECE Flag Count
52. Down/Up Ratio
53. Avg Packet Size
54. Avg Fwd Segment Size
55. Avg Bwd Segment Size
56. Fwd Avg Bytes/Bulk
57. Fwd Avg Packets/Bulk
58. Fwd Avg Bulk Rate
59. Bwd Avg Bytes/Bulk
60. Bwd Avg Packets/Bulk
61. Bwd Avg Bulk Rate
62. Subflow Fwd Packets
63. Subflow Fwd Bytes
64. Subflow Bwd Packets
65. Subflow Bwd Bytes
66. Init Fwd Win Bytes
67. Init Bwd Win Bytes
68. Fwd Act Data Packets
69. Fwd Seg Size Min
70. Active Mean
71. Active Std
72. Active Max
73. Active Min
74. Idle Mean
75. Idle Std
76. Idle Max
77. Idle Min

---

## 8. Phase 1 Final Architecture

```text
CIC-IDS2017
      â†“
Dataset Cleaning
      â†“
Binary Label Conversion
(BENIGN = 0 / ATTACK = 1)
      â†“
77-Feature Dataset
      â†“
Stratified Train/Test Split
      â†“
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Random Forest                â”‚
â”‚ XGBoost                      â”‚
â”‚ KNN + Scaler                 â”‚
â”‚ CNN + Scaler                 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
      â†“
Evaluation
      â†“
Saved Models + Feature Contract
```

---

## 9. Phase 1 Outcome

Phase 1 successfully produced a reusable machine-learning detection layer for Sentinel.

By the end of the phase:

- CIC-IDS2017 had been cleaned and standardized.
- The task had been converted to binary intrusion detection.
- A common 77-feature schema had been established.
- Four different models had been trained.
- The models had been evaluated using a common held-out test set.
- Required scalers were saved.
- Feature ordering was saved.
- Deployment-ready model artifacts were exported.
- XGBoost was chosen as the initial production model for the next phase.

---

## 10. Transition to Phase 2

Phase 1 answered:

> **Can Sentinel learn to distinguish benign traffic from malicious traffic?**

Phase 2 would answer:

> **Can that trained model be turned into a real software service that other systems can call?**

The next phase therefore focused on exposing the trained XGBoost model through a FastAPI inference API.

---

## Phase Status

**Phase 1 â€” ML Training & Evaluation: âœ… COMPLETE**
