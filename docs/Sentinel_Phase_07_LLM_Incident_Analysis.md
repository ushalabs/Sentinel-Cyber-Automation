# Sentinel - Phase 07: LLM Incident Analysis

**Project:** Sentinel
**Phase:** 7 - LLM Incident Analysis
**Status:** Complete
**Completed:** September 2026

---

## 1. Objective

Phase 7 adds a structured LLM incident-analysis layer on top of the existing Sentinel detection and threat-intelligence pipeline.

Before this phase, Sentinel could classify flows, persist detections, automate routing through n8n, enrich ATTACK detections with AbuseIPDB, and write threat intelligence back into PostgreSQL.

Phase 7 extends the ATTACK path so Sentinel can explain and contextualize the incident using an LLM without allowing the LLM to replace the ML detector or the threat-intelligence provider.

The completed phase adds:

- Gemini API integration
- compact incident-context construction
- structured JSON output
- Pydantic validation
- LLM analysis persistence
- explicit analysis status and error tracking
- ATTACK-only analysis guards
- automatic n8n integration
- combined ML + threat-intelligence + LLM responses
- BENIGN regression validation

---

## 2. Phase 7 Architecture

```text
Network Flow
    |
    v
FastAPI
    |
    v
XGBoost
    |
    v
BENIGN / ATTACK
    |
    v
PostgreSQL
    |
    v
n8n
    |
    +-- BENIGN --> SAFE Response
    |
    `-- ATTACK
          |
          v
       AbuseIPDB
          |
          v
   Threat Enrichment
          |
          v
Save Threat Intelligence
          |
          v
Analyze Incident with LLM
          |
          v
Google Gemini
          |
          v
Structured JSON
          |
          v
Pydantic Validation
          |
          v
Save LLM Analysis
          |
          v
Combined ATTACK Response
```

The LLM does not receive the full 77-feature vector. It receives the interpreted detection result, network metadata, and threat-intelligence context.

---

## 3. Database Expansion

The `detections` table was extended with:

```sql
ALTER TABLE detections
ADD COLUMN llm_provider VARCHAR(50),
ADD COLUMN llm_model VARCHAR(100),
ADD COLUMN incident_analysis JSONB,
ADD COLUMN analysis_status VARCHAR(20) DEFAULT 'NOT_STARTED',
ADD COLUMN analysis_error TEXT,
ADD COLUMN analyzed_at TIMESTAMPTZ;
```

The new fields represent the provider, model, structured analysis JSONB, analysis state, provider/validation errors, and completion timestamp.

---

## 4. SQLAlchemy Model Update

`backend/app/models.py` was updated with SQLAlchemy 2-style mappings for the new LLM fields.

The database migration was performed manually in PostgreSQL. The SQLAlchemy update allows the backend to read and write the new columns.

---

## 5. Structured Incident Schema

`main.py` defines a strict Pydantic model:

```python
class IncidentAnalysis(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_reason: str
    summary: str
    likely_activity: str
    reasoning: list[str]
    risk_factors: list[str]
    recommended_actions: list[str]
    analyst_note: str
```

This prevents unrestricted LLM prose from being trusted directly.

---

## 6. Dedicated LLM Analysis Service

A new service file was created:

```text
backend/app/services/llm_analysis.py
```

Its responsibilities are:

```text
Detection
   |
   v
Build incident context
   |
   v
Build analysis prompt
   |
   v
Call Gemini
   |
   v
Receive structured JSON
   |
   v
Return Python dictionary
```

Provider-specific code remains outside `main.py`.

---

## 7. Incident Context and Prompt Rules

The LLM receives:

```text
Detection
- id
- prediction
- attack
- confidence
- attack_probability
- model

Network
- source_ip
- destination_ip
- source_port
- destination_port
- transport_protocol
- observed_at

Threat Intelligence
- provider
- AbuseIPDB JSON
- enriched_at
```

The prompt tells Gemini to analyze only supplied evidence, avoid inventing logs or vulnerabilities, distinguish evidence from inference, use cautious language, treat threat-intelligence reports as context rather than proof, and keep recommendations advisory.

---

## 8. Gemini Integration

The working Phase 7 development provider and model are:

```text
Google Gemini
gemini-3.5-flash-lite
```

The API key is loaded from:

```text
backend/.env
```

and is not committed to Git.

### Validation evidence

A real API request from Sentinel returned the expected response:

![Gemini API connection](assets/phase%206/gemini%20connection.png)

---

## 9. Structured Output and Validation

Gemini is configured to return `application/json` matching Sentinel's incident-analysis JSON schema.

The response passes through:

```text
Gemini structured output
        |
        v
JSON parsing
        |
        v
Pydantic validation
        |
        v
Trusted application data
```

The structured result is only persisted after validation succeeds.

---

## 10. Analysis API Endpoint

A new endpoint was added:

```text
POST /detections/{detection_id}/analysis
```

The endpoint:

1. checks that the detection exists
2. rejects BENIGN detections
3. requires threat intelligence first
4. sets `analysis_status = PENDING`
5. calls Gemini
6. validates the result with Pydantic
7. stores the analysis as JSONB
8. sets `analysis_status = COMPLETED`

If the provider or validation fails, the endpoint stores:

```text
analysis_status = FAILED
analysis_error = actual error
```

without deleting the original incident.

---

## 11. Controlled End-to-End Analysis

A controlled ATTACK record was created specifically for integration testing.

It used:

```text
source_ip: 8.8.8.8
destination_ip: 192.168.1.10
destination_port: 22
protocol: TCP
prediction: ATTACK
confidence: 0.99
```

This was not presented as a genuine XGBoost-detected attack.

Threat intelligence showed that the public source was associated with Google LLC, was whitelisted, and had an abuse confidence score of 0. Gemini therefore returned a cautious `LOW` severity analysis rather than blindly treating the fabricated ML ATTACK as confirmed malicious activity.

### Validation evidence

![Structured LLM incident response](assets/phase%206/terminal%20result.png)

---

## 12. n8n Integration

The published ATTACK branch was extended with:

```text
Analyze Incident with LLM
```

after:

```text
Save Threat Intelligence
```

The final ATTACK branch is:

```text
Webhook
   |
   v
IF
   |
   v
Check Source IP Reputation
   |
   v
Prepare Attack Alert
   |
   v
Save Threat Intelligence
   |
   v
Analyze Incident with LLM
   |
   v
Respond to Webhook (Attack)
```

### Validation evidence

The complete production ATTACK path executed successfully:

![n8n Phase 7 production execution](assets/phase%206/n8n%20result.png)

---

## 13. Status vs Severity

During validation, the hard-coded outer status:

```text
CRITICAL
```

was replaced with:

```text
ATTACK_DETECTED
```

The LLM severity remains dynamic:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

This separates:

```text
status
→ what the ML detector classified
```

from:

```text
incident_analysis.severity
→ the overall incident assessment after enrichment and analysis
```

This prevents every ML ATTACK from being described as automatically critical.

---

## 14. External Provider Failure Handling

During development, Gemini returned a temporary:

```text
503 UNAVAILABLE
```

high-demand response.

Sentinel handled the failure safely:

```text
Gemini request fails
        |
        v
Exception caught
        |
        v
analysis_status = FAILED
        |
        v
analysis_error = provider error
        |
        v
Original detection remains intact
```

The model was then changed to an available free-tier development model and the full analysis succeeded.

---

## 15. Safety and Regression Validation

Three key safety cases were validated.

### BENIGN traffic

Expected:

```text
SAFE response
No AbuseIPDB lookup
No Gemini analysis
```

Result: Passed.

### ATTACK without threat intelligence

Expected:

```text
400
Threat intelligence must exist before LLM analysis
```

Result: Passed.

### Nonexistent detection ID

Expected:

```text
404
Detection not found
```

Result: Passed.

### Validation evidence

![Phase 7 safety validation](assets/phase%206/validation.png)

---

## 16. Temporary Test Data Cleanup

Controlled ATTACK records created for Phase 7 integration and safety testing were deleted after validation.

The normal BENIGN regression record was retained.

Gaps in PostgreSQL IDs are expected because sequences do not rewind after failed or deleted inserts.

---

## 17. Files Modified in Phase 7

Backend:

```text
backend/app/main.py
backend/app/models.py
backend/app/services/llm_analysis.py
```

Automation:

```text
automation/sentinel_detection_automation.json
```

Documentation:

```text
docs/Sentinel_Phase_07_LLM_Incident_Analysis.md
docs/assets/phase 6/
docs/assets/readme/
```

---

## 18. Major Concepts Learned

Phase 7 introduced:

- LLMs as advisory analysis layers rather than detection authorities
- structured model output
- Pydantic validation
- JSONB persistence for evolving structured analysis
- provider/model tracking
- status vs severity separation
- external-provider failure handling
- ATTACK-only analysis guards
- separation of prompt/provider logic from API routing

---

## 19. Phase 7 Outcome

Phase 7 is complete.

Sentinel now supports:

- Google Gemini integration
- structured LLM incident analysis
- evidence-aware severity reasoning
- likely-activity interpretation
- risk factors
- recommended analyst actions
- analyst notes
- Pydantic output validation
- JSONB analysis persistence
- LLM provider/model tracking
- analysis timestamps
- explicit analysis status
- provider error persistence
- ATTACK-only guards
- threat-intelligence prerequisite checks
- automatic n8n analysis
- combined Phase 6 + Phase 7 responses
- BENIGN regression compatibility
- external LLM failure handling

Sentinel has moved from automated detection and enrichment into automated incident interpretation.

---

## 20. Transition to Phase 8

The next phase is:

```text
Phase 8 - Human Approval & Automated Response
```

The intended boundary is:

```text
Detection
   |
   v
Threat Intelligence
   |
   v
LLM Analysis
   |
   v
Recommended Actions
   |
   v
Human Approval
   |
   +-- Reject
   |
   `-- Approve
         |
         v
Controlled Response Action
```

The LLM remains advisory. Potentially disruptive actions will require a separate approval layer rather than being executed directly from model output.
