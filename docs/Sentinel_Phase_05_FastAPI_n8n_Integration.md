# Sentinel â€” Phase 5 Technical Record
## FastAPI â†’ n8n Integration

**Project:** Sentinel
**Phase:** 5 â€” Sentinel to n8n Integration
**Status:** âœ… Complete
**Completed:** September 2026

---

## 1. Objective

Phase 5 connected Sentinel's real FastAPI backend to the n8n automation workflow created in Phase 4.

Before this phase, n8n could receive Sentinel-style detection JSON and route ATTACK and BENIGN events correctly, but those payloads were still being sent manually from PowerShell.

The Phase 5 objective was:

> Automatically trigger n8n from Sentinel after each real model prediction.

Target flow:

```text
77 Network Features
        â†“
POST /predict
        â†“
FastAPI
        â†“
XGBoost
        â†“
PostgreSQL
        â†“
Detection Event JSON
        â†“
n8n Production Webhook
        â†“
IF attack?
   â†™        â†˜
 TRUE      FALSE
  â†“          â†“
CRITICAL     SAFE
```

---

## 2. Starting Point

Sentinel already had:

- XGBoost model serving
- `POST /predict`
- PostgreSQL persistence
- detection IDs
- published n8n workflow
- working production webhook
- ATTACK / BENIGN routing

The missing piece was the automatic FastAPI â†’ n8n connection.

---

## 3. n8n Webhook Configuration

The published n8n production webhook was added to:

```text
backend/.env
```

as:

```env
N8N_WEBHOOK_URL=http://localhost:5678/webhook/sentinel-detection
```

This keeps integration configuration outside source code.

The existing `.gitignore` already excludes `.env`.

---

## 4. Webhook Configuration Test

Sentinel verified that Python could read:

```text
N8N_WEBHOOK_URL
```

from the environment.

The resolved value was:

```text
http://localhost:5678/webhook/sentinel-detection
```

---

## 5. HTTP Client

The Python package:

```text
httpx
```

was installed in Sentinel's virtual environment.

Its job is to let FastAPI make outbound HTTP requests.

Conceptually:

```text
Sentinel Python
      â†“
httpx
      â†“
HTTP POST
      â†“
n8n
```

---

## 6. Direct Python â†’ n8n Test

Before modifying `/predict`, a temporary script was created:

```text
backend/test_n8n_connection.py
```

It:

1. loaded the webhook URL from `.env`
2. built a fake detection payload
3. sent it to n8n
4. received the automation response

Example payload:

```json
{
  "detection_id": 999,
  "prediction": "ATTACK",
  "attack": true,
  "confidence": 0.995,
  "model": "XGBoost"
}
```

Expected response:

```json
{
  "status": "CRITICAL",
  "message": "Sentinel detected malicious network traffic",
  "detection_id": 999,
  "model": "XGBoost",
  "confidence": 0.995
}
```

This confirmed that Python could call the published n8n workflow successfully.

---

## 7. Automation Service Layer

The n8n integration logic was moved into:

```text
backend/app/services/automation.py
```

A reusable function was created:

```python
send_detection_to_n8n(...)
```

Its responsibilities are:

- receive detection data
- build the webhook payload
- send the POST request
- enforce a timeout
- raise an error for failed HTTP responses
- return n8n's JSON response

Payload fields:

```text
detection_id
prediction
attack
confidence
model
```

---

## 8. Automation Service Test

The reusable service function was tested directly.

A sample ATTACK event was passed into:

```python
send_detection_to_n8n(...)
```

and the expected CRITICAL response came back from n8n.

This confirmed the service was ready to be used by FastAPI.

---

## 9. Integration into `/predict`

`main.py` imported:

```python
from app.services.automation import send_detection_to_n8n
```

The `/predict` flow changed from:

```text
Input
 â†“
XGBoost
 â†“
PostgreSQL
 â†“
Response
```

to:

```text
Input
 â†“
XGBoost
 â†“
PostgreSQL
 â†“
n8n
 â†“
Automation Response
 â†“
FastAPI Response
```

---

## 10. Integration Order

The n8n call happens only after the detection has been saved to PostgreSQL.

Order:

```text
1. Run XGBoost prediction
2. Create Detection record
3. Commit to PostgreSQL
4. Refresh detection
5. Obtain real detection.id
6. Send event to n8n
7. Return combined response
```

This ensures n8n receives a real persistent detection ID.

---

## 11. Automation Error Handling

The n8n call uses its own `try/except`.

This means:

```text
Prediction âœ…
Database âœ…
Automation âŒ
```

does not incorrectly become:

```text
Prediction âŒ
```

If n8n is unavailable, Sentinel can still return the valid prediction and stored detection while reporting that automation failed.

This is an important production-reliability decision.

---

## 12. Updated `/predict` Response

The response was expanded with:

```text
automation_triggered
automation_result
```

Example:

```json
{
  "detection_id": 2,
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.999966,
  "attack_probability": 0.000034,
  "threshold": 0.5,
  "model": "XGBoost",
  "created_at": "...",
  "automation_triggered": true,
  "automation_result": {
    "status": "SAFE",
    "message": "Sentinel classified traffic as benign",
    "detection_id": 2,
    "model": "XGBoost",
    "confidence": 0.9999658
  }
}
```

---

## 13. Real FastAPI â†’ n8n Test

The existing Sentinel prediction test was run through:

```text
POST /predict
```

The synthetic all-zero 77-feature record was classified as BENIGN.

The real execution became:

```text
test_prediction.py
      â†“
FastAPI /predict
      â†“
XGBoost
      â†“
BENIGN
      â†“
PostgreSQL
      â†“
detection_id = 2
      â†“
send_detection_to_n8n()
      â†“
n8n Production Webhook
      â†“
IF attack = false
      â†“
Prepare Benign Result
      â†“
SAFE
      â†“
FastAPI
```

The API returned:

```text
automation_triggered = true
```

which confirmed the integration worked automatically.

---

## 14. n8n Execution Verification

The integration was also verified visually in n8n.

Inside the workflow's:

```text
Executions
```

tab, the production execution showed:

```text
Webhook
   â†“
IF
   â†“ FALSE
Prepare Benign Result
   â†“
Respond to Webhook
```

This confirmed that the event truly came from FastAPI and passed through the published workflow.

---

## 15. Final Phase 5 Architecture

```text
               SENTINEL â€” PHASE 5

          77-Feature Network Payload
                    â†“
              POST /predict
                    â†“
                 FastAPI
                    â†“
                 XGBoost
                    â†“
           BENIGN / ATTACK
                    â†“
          Create Detection Record
                    â†“
               PostgreSQL
                    â†“
             detection.id
                    â†“
       send_detection_to_n8n()
                    â†“
                 httpx
                    â†“
       n8n Production Webhook
                    â†“
               IF attack?
              â†™          â†˜
           TRUE          FALSE
            â†“              â†“
         CRITICAL          SAFE
            â†“              â†“
          n8n Response Returned
                    â†“
              FastAPI Response
```

---

## 16. Files Added / Modified

### Added

```text
backend/test_n8n_connection.py
backend/app/services/automation.py
```

### Modified

```text
backend/.env
backend/app/main.py
```

### Existing files involved

```text
backend/app/database.py
backend/app/models.py
backend/test_prediction.py
```

---

## 17. Concepts Learned

Phase 5 introduced:

### Outbound HTTP Requests
FastAPI can call external services rather than only receive requests.

### Service Layer
Integration logic was separated from `main.py`.

### Environment-Based Configuration
Webhook URLs live in `.env`.

### Backend â†’ Automation Integration
FastAPI can trigger n8n through a production webhook.

### Event Payload Design
Only required detection fields are sent to n8n.

### Failure Isolation
Automation failure is handled separately from prediction and persistence.

### Execution History
n8n's Executions tab provides a visual audit trail.

### End-to-End Integration
One `/predict` request can now trigger multiple systems automatically.

---

## 18. Reliability Decisions

Phase 5 includes:

- webhook URL in `.env`
- HTTP timeout
- HTTP error checking
- isolated n8n error handling
- PostgreSQL save before automation
- real persistent detection ID passed to n8n
- automation success reported in API response
- n8n execution history for debugging

---

## 19. Validation Status

The core Phase 5 objective was fully validated:

```text
Real FastAPI Prediction
        â†“
PostgreSQL Save
        â†“
Automatic n8n Trigger
        â†“
Workflow Execution
        â†“
Response Back to FastAPI
```

A real BENIGN prediction successfully triggered the SAFE branch.

The ATTACK branch had already been validated independently in Phase 4 through both test and production webhook calls.

A real-dataset ATTACK â†’ XGBoost â†’ n8n CRITICAL test was intentionally deferred to the final real-time validation phase before deployment.

---

## 20. Phase 5 Outcome

By the end of Phase 5:

- Sentinel could read the n8n production webhook from `.env`.
- Python communicated with n8n using `httpx`.
- n8n integration logic was isolated in a reusable service.
- `/predict` automatically triggered n8n after saving a detection.
- n8n received real Sentinel prediction data.
- the published workflow routed the event correctly.
- n8n returned structured automation output.
- FastAPI returned the automation result to the caller.
- n8n's Executions page confirmed the real workflow path.
- no manual PowerShell request to n8n was required.

Sentinel evolved from:

> **A machine-learning API with automation beside it**

into:

> **A machine-learning backend that actively triggers automation as part of its detection pipeline.**

---

## 21. Transition to Phase 6

Phase 5 answered:

> **Can Sentinel automatically trigger n8n after a real prediction?**

The answer was yes.

Phase 6 will add external cybersecurity context through threat-intelligence enrichment.

Target flow:

```text
Sentinel Detection
       â†“
n8n
       â†“
Threat Intelligence API
       â†“
IP / Reputation / Risk Data
       â†“
Enriched Incident
```

---

## Phase Status

**Phase 5 â€” FastAPI â†’ n8n Integration: âœ… COMPLETE**
