# Sentinel â€” Phase 2 Technical Record
## Model Serving with FastAPI

**Project:** Sentinel
**Phase:** 2 â€” Model Serving & Inference API
**Status:** âœ… Complete
**Completed:** September 2026

---

## 1. Objective

Phase 2 transformed Sentinel from a collection of trained ML models into a real software service.

The primary goal was to take the trained XGBoost intrusion-detection model from Phase 1 and expose it through a FastAPI backend so other applications, automation workflows, or future frontend components could send network-flow data and receive predictions.

Phase 2 established the first production-style inference pipeline:

```text
Input JSON
   â†“
FastAPI
   â†“
Feature Validation
   â†“
77-Feature Ordering
   â†“
XGBoost Inference
   â†“
BENIGN / ATTACK
   â†“
JSON Response
```

---

## 2. Starting Point

At the beginning of Phase 2, Sentinel already had:

- Four trained binary classifiers
- XGBoost selected as the initial production model
- A saved XGBoost model:
  `sentinel_xgboost_binary_v1.json`
- A saved feature-order file:
  `sentinel_feature_columns_v1.joblib`
- A known 77-feature input schema
- Binary classification convention:
  - `0 = BENIGN`
  - `1 = ATTACK`

The project structure already contained:

```text
Sentinel/
â””â”€â”€ ML Models/
    â”œâ”€â”€ CNN/
    â”œâ”€â”€ KNN/
    â”œâ”€â”€ Random Forest/
    â””â”€â”€ XGBoost/
```

---

## 3. Local Python Environment

A dedicated backend environment was created for Sentinel.

### Backend folder

```text
Sentinel/backend
```

### Virtual environment

Created with:

```powershell
python -m venv venv
```

Activated with:

```powershell
.\venv\Scripts\Activate.ps1
```

The virtual environment isolates Sentinel's Python dependencies from the global system Python installation.

---

## 4. Backend Dependencies

The following packages were installed inside the Sentinel virtual environment:

```text
fastapi
uvicorn[standard]
xgboost
scikit-learn
joblib
numpy
pandas
```

These packages provide:

- **FastAPI** â€” REST API framework
- **Uvicorn** â€” ASGI server
- **XGBoost** â€” model loading and inference
- **joblib** â€” loading the saved feature schema
- **NumPy** â€” numeric array construction and validation
- **Pandas / scikit-learn** â€” ML-related support

---

## 5. FastAPI Application

The backend application was created at:

```text
backend/app/main.py
```

The initial FastAPI object defined Sentinel's API metadata:

```python
app = FastAPI(
    title="Sentinel API",
    description="Backend API for Sentinel Network Intrusion Detection System",
    version="0.2.0"
)
```

---

## 6. Initial API Endpoints

Two basic endpoints were created first to verify that the backend was working.

### Root endpoint

```http
GET /
```

Example response:

```json
{
  "project": "Sentinel",
  "status": "online",
  "phase": 2,
  "model": "XGBoost"
}
```

### Health endpoint

```http
GET /health
```

Used to confirm that the API was alive and the model had loaded correctly.

Example response:

```json
{
  "status": "healthy",
  "model_loaded": true,
  "model": "XGBoost",
  "expected_features": 77
}
```

---

## 7. Swagger UI

FastAPI automatically exposed interactive API documentation through Swagger UI.

The local documentation endpoint was:

```text
http://127.0.0.1:8000/docs
```

This made it possible to test Sentinel's API without building a frontend.

---

## 8. XGBoost Model Verification

Before building the prediction endpoint, the saved model was validated.

The model loaded successfully from:

```text
ML Models/XGBoost/sentinel_xgboost_binary_v1.json
```

The model reported:

```text
EXPECTED FEATURES: 77
```

This confirmed that the trained XGBoost artifact was valid and deployment-ready.

---

## 9. Feature Schema Verification

The saved feature-order file was then loaded from:

```text
ML Models/XGBoost/sentinel_feature_columns_v1.joblib
```

The saved feature list contained:

```text
77 features
```

This matched the XGBoost model exactly:

```text
XGBoost expected features: 77
Saved feature list:         77
```

This check was critical because inference must use the exact same feature structure used during training.

---

## 10. Model Loading in FastAPI

The backend was updated so the XGBoost model and feature list load when the application starts.

The backend resolves paths relative to the Sentinel project root and loads:

```text
sentinel_xgboost_binary_v1.json
sentinel_feature_columns_v1.joblib
```

A runtime validation ensures that the model and feature list remain compatible.

If the feature count does not match the model's expected input count, the backend raises an error instead of serving invalid predictions.

---

## 11. Model Information Endpoint

An additional endpoint was created:

```http
GET /model-info
```

It exposes:

- model name
- feature count
- complete feature list

Example structure:

```json
{
  "model": "XGBoost",
  "feature_count": 77,
  "features": [
    "Protocol",
    "Flow Duration",
    "...",
    "Idle Min"
  ]
}
```

This endpoint is useful for debugging and future integrations.

---

## 12. Prediction Request Schema

A FastAPI/Pydantic request model was introduced:

```python
class PredictionRequest(BaseModel):
    features: dict[str, float]
```

The API therefore expects prediction requests in this general structure:

```json
{
  "features": {
    "Protocol": 6,
    "Flow Duration": 12345,
    "...": 0
  }
}
```

---

## 13. Feature Validation

Before inference, Sentinel checks that all 77 required features are present.

If one or more fields are missing, Sentinel rejects the request with an HTTP 400 response instead of silently producing an unreliable prediction.

This protects the model from malformed input.

---

## 14. Feature Reordering

Incoming JSON does not need to preserve training order.

Sentinel uses the saved `feature_columns` list to reconstruct the exact training-time order:

```text
Incoming JSON
   â†“
Feature-name lookup
   â†“
Reorder to saved 77-feature schema
   â†“
Model input
```

This is one of the most important deployment safeguards added in Phase 2.

---

## 15. Numeric Validation

The ordered feature values are converted into a NumPy float array.

Sentinel verifies that all values are finite.

Requests containing:

```text
NaN
+Infinity
-Infinity
```

are rejected before reaching the model.

---

## 16. XGBoost DMatrix

The validated feature array is converted into an XGBoost `DMatrix`:

```python
dmatrix = xgb.DMatrix(
    values,
    feature_names=feature_columns
)
```

This becomes the actual inference input passed into the trained model.

---

## 17. Prediction Endpoint

The main Phase 2 endpoint was created:

```http
POST /predict
```

The inference process is:

```text
Request received
   â†“
Validate 77 features
   â†“
Restore training feature order
   â†“
Convert to NumPy array
   â†“
Create XGBoost DMatrix
   â†“
Run model.predict()
   â†“
Get attack probability
   â†“
Apply threshold
   â†“
Return JSON result
```

---

## 18. Prediction Logic

The model returns an attack probability.

Sentinel initially uses:

```text
threshold = 0.5
```

Classification logic:

```text
attack_probability >= 0.5 â†’ ATTACK
attack_probability <  0.5 â†’ BENIGN
```

The API also reports confidence.

For an attack:

```text
confidence = attack_probability
```

For benign traffic:

```text
confidence = 1 - attack_probability
```

---

## 19. Prediction Response Format

The Phase 2 response structure includes:

```json
{
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.999966,
  "attack_probability": 0.000034,
  "threshold": 0.5,
  "model": "XGBoost"
}
```

This format was intentionally designed to be easy for:

- frontends
- dashboards
- databases
- automation tools
- webhooks
- future AI analysis layers

to consume.

---

## 20. Synthetic Inference Test

A separate test script was created:

```text
backend/test_prediction.py
```

The script:

1. loaded the saved 77-feature schema
2. created a synthetic all-zero input record
3. sent it to:
   `POST /predict`
4. received the model response

The returned result was approximately:

```json
{
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.999966,
  "attack_probability": 0.000034,
  "threshold": 0.5,
  "model": "XGBoost"
}
```

The purpose of this test was **not** to validate real-world classification quality.

It proved that the complete serving pipeline worked:

```text
Python Test Script
      â†“
HTTP POST
      â†“
FastAPI
      â†“
77-Feature Validation
      â†“
XGBoost
      â†“
Prediction
      â†“
JSON Response
```

---

## 21. Backend Project Structure After Phase 2

By the end of Phase 2, Sentinel's backend looked approximately like:

```text
Sentinel/
â”œâ”€â”€ ML Models/
â”‚   â””â”€â”€ XGBoost/
â”‚       â”œâ”€â”€ sentinel_xgboost_binary_v1.json
â”‚       â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚
â””â”€â”€ backend/
    â”œâ”€â”€ app/
    â”‚   â””â”€â”€ main.py
    â”‚
    â”œâ”€â”€ venv/
    â””â”€â”€ test_prediction.py
```

---

## 22. Concepts Learned

Phase 2 introduced several important backend and automation foundations:

### Virtual Environments
How to isolate project dependencies.

### REST APIs
How software systems communicate through HTTP.

### API Endpoints
How specific routes expose application functionality.

### HTTP Methods
Especially:

```text
GET
POST
```

### JSON
The main data-exchange format used between systems.

### FastAPI
How to build a modern Python API backend.

### Swagger / OpenAPI
How APIs can be documented and tested interactively.

### Model Serving
How to take a trained ML model out of a notebook and make it callable by other software.

### Feature Contracts
Why production inference must preserve the exact feature schema used during training.

### Request Validation
How malformed inputs are rejected before reaching the ML model.

### Inference Pipelines
How data flows from an external request through preprocessing into an ML model and back as a response.

These concepts later become essential for AI automation because automation tools communicate with services using the same APIs, HTTP requests, JSON payloads, and webhooks.

---

## 23. Problems Encountered

### Python was not initially installed locally

The backend could not create a virtual environment because Windows could not locate Python.

Python 3.12 was installed locally before backend development continued.

### Python installation issues

The first Python installation attempts encountered:

- a corrupted `.msix` package
- a Windows integrity/hash error
- a `winget` network timeout

The issue was resolved by installing Python using the standard Windows executable installer.

### Browser favicon 404

Uvicorn logged:

```text
GET /favicon.ico 404 Not Found
```

This was harmless.

The browser requested an icon that Sentinel did not yet provide.

---

## 24. Security / Reliability Decisions

Phase 2 included several early production-style safeguards:

- exact model-feature count validation
- missing-feature detection
- feature-name-based ordering
- non-finite numeric rejection
- explicit prediction threshold
- structured JSON responses
- separation between ML artifacts and backend code

These decisions reduce the chance of producing valid-looking but incorrect inference results.

---

## 25. Remaining Validation

The synthetic all-zero request confirmed that the serving pipeline works.

A later validation step should also test:

- one known BENIGN record from CIC-IDS2017
- one known ATTACK record from CIC-IDS2017

This verifies that the deployed model reproduces expected labels using real dataset samples.

---

## 26. Phase 2 Final Architecture

```text
                SENTINEL â€” PHASE 2

External Client / Test Script
            â†“
        HTTP POST
            â†“
       FastAPI API
            â†“
     Request Validation
            â†“
   77-Feature Reordering
            â†“
      NumPy Conversion
            â†“
      XGBoost DMatrix
            â†“
    Trained XGBoost Model
            â†“
     Attack Probability
            â†“
    BENIGN / ATTACK Logic
            â†“
       JSON Response
```

---

## 27. Phase 2 Outcome

By the end of Phase 2:

- Sentinel had a working local backend.
- The trained XGBoost model could load outside Jupyter/Colab.
- The backend verified the model's 77-feature requirement.
- The saved feature schema was integrated into production inference.
- FastAPI exposed health and model-information endpoints.
- A real `/predict` endpoint was created.
- Incoming requests were validated.
- Feature ordering was preserved correctly.
- XGBoost inference worked through HTTP.
- The backend returned structured prediction responses.
- Swagger UI provided interactive API testing.
- A test client successfully completed an end-to-end inference request.

Sentinel had therefore evolved from a trained ML experiment into a callable software service.

---

## 28. Transition to Phase 3

Phase 2 answered:

> **Can Sentinel expose its trained intrusion-detection model as a real API?**

The answer was yes.

However, predictions disappeared after the HTTP response.

Phase 3 would therefore answer:

> **Can Sentinel permanently store and retrieve every detection event?**

The next phase introduced PostgreSQL, SQLAlchemy, persistent detection records, history retrieval, and filtering.

---

## Phase Status

**Phase 2 â€” Model Serving & Inference API: âœ… COMPLETE**
