# Sentinel - Phase 08: Analyst Dashboard, Human Approval & Response

**Project:** Sentinel
**Phase:** 8 - Analyst Dashboard, Human Approval & Response
**Status:** Complete
**Completed:** September 2026

---

## 1. Objective

Phase 8 transforms Sentinel from a backend-heavy security pipeline into an analyst-facing incident-response system.

Before this phase, Sentinel could:

- classify traffic with XGBoost
- persist detections in PostgreSQL
- automate ATTACK and BENIGN routing with n8n
- enrich ATTACK detections with AbuseIPDB
- run structured Gemini incident analysis
- persist threat intelligence and LLM output

Phase 8 adds:

- a live Next.js analyst dashboard
- clickable incident history
- detailed incident views
- light and dark themes
- human approval and rejection
- analyst notes
- explicit response-action selection
- response-state persistence
- allowlisted response execution
- simulated blocking for safe development
- browser-only incident handling without PowerShell

---

## 2. Phase 8 Architecture

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
review_status = PENDING
   |
   v
Next.js Analyst Dashboard
   |
   v
Human Review
   |
   +-------------------+
   |                   |
   v                   v
REJECT              APPROVE
   |                   |
   v                   v
No Action       response_status = PENDING
                       |
                       v
              Execute Allowlisted Action
                       |
                       v
                 EXECUTED / FAILED
```

The dashboard is an interface layer. It does not duplicate the backend's validation or security rules.

---

## 3. PostgreSQL Expansion

Phase 8 added these fields to the `detections` table:

```sql
ALTER TABLE detections
ADD COLUMN review_status VARCHAR(20) DEFAULT 'NOT_REQUIRED',
ADD COLUMN review_note TEXT,
ADD COLUMN reviewed_at TIMESTAMPTZ,
ADD COLUMN response_action VARCHAR(50),
ADD COLUMN response_status VARCHAR(20) DEFAULT 'NOT_STARTED',
ADD COLUMN response_result JSONB,
ADD COLUMN responded_at TIMESTAMPTZ;
```

The fields represent:

```text
review_status
→ NOT_REQUIRED / PENDING / APPROVED / REJECTED

review_note
→ analyst explanation

reviewed_at
→ human-review timestamp

response_action
→ selected allowlisted action

response_status
→ NOT_STARTED / PENDING / EXECUTED / FAILED

response_result
→ structured JSONB response outcome

responded_at
→ response completion timestamp
```

---

## 4. SQLAlchemy Mapping

`backend/app/models.py` was updated with SQLAlchemy 2-style mappings for all new review and response fields.

A development issue was discovered during testing where several response fields were accidentally placed outside the `Detection` class because of indentation.

That caused:

```text
AttributeError:
'Detection' object has no attribute 'response_status'
```

The mapping was corrected so all Phase 8 fields are now part of the SQLAlchemy model and persist correctly.

---

## 5. Review Request Schema

A new Pydantic request schema was added:

```python
class ReviewDecisionRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    action: str | None = None
    note: str | None = None
```

This allows one endpoint to support both approval and rejection.

Approval example:

```json
{
  "decision": "APPROVE",
  "action": "BLOCK_SOURCE_IP",
  "note": "Approved after reviewing the available evidence."
}
```

Rejection example:

```json
{
  "decision": "REJECT",
  "action": null,
  "note": "No response action is required."
}
```

---

## 6. Automatic Review State

When an ATTACK analysis completes successfully, Sentinel now sets:

```text
review_status = PENDING
```

This creates a clear transition:

```text
ATTACK
→ Threat Intelligence
→ LLM Analysis COMPLETED
→ Human Review PENDING
```

The incident is then visible in the analyst dashboard and ready for review.

---

## 7. Human Review Endpoint

A new endpoint was added:

```text
POST /detections/{detection_id}/review
```

The endpoint verifies:

```text
Detection exists
ATTACK == true
LLM analysis == COMPLETED
Incident has not already been reviewed
```

If approved:

```text
review_status = APPROVED
response_action = selected action
response_status = PENDING
review_note = analyst note
reviewed_at = timestamp
```

If rejected:

```text
review_status = REJECTED
response_action = NULL
response_status = NOT_STARTED
review_note = analyst note
reviewed_at = timestamp
```

---

## 8. Controlled Response Service

A dedicated backend service was created:

```text
backend/app/services/response_service.py
```

The service uses an explicit allowlist:

```text
BLOCK_SOURCE_IP
LOG_ONLY
```

This prevents arbitrary model-generated or user-provided commands from being executed.

For example, unsupported actions cannot become operating-system commands simply because an LLM suggested them.

---

## 9. Response Modes

### BLOCK_SOURCE_IP

During Phase 8 this action runs in:

```text
SIMULATION
```

mode.

A successful simulated response returns structured information such as:

```json
{
  "action": "BLOCK_SOURCE_IP",
  "source_ip": "203.0.113.99",
  "executed": true,
  "mode": "SIMULATION",
  "message": "Simulated blocking of source IP 203.0.113.99"
}
```

No real firewall modification occurs during development.

### LOG_ONLY

This response records the incident without taking a network action.

It is useful when the analyst wants to acknowledge the event but does not want Sentinel to block anything.

---

## 10. Protected Response Endpoint

A new endpoint was added:

```text
POST /detections/{detection_id}/respond
```

The endpoint enforces:

```text
Detection exists
ATTACK == true
review_status == APPROVED
response_action exists
response has not already executed
```

Only after these checks does FastAPI call the allowlisted response service.

Successful execution stores:

```text
response_status = EXECUTED
response_result = structured JSONB
responded_at = timestamp
```

Failure stores:

```text
response_status = FAILED
response_result = error information
responded_at = timestamp
```

---

## 11. Human Approval Gate Validation

A controlled test incident was created with:

```text
review_status = PENDING
```

Calling `/respond` before approval returned:

```text
403 Forbidden
Human approval is required before executing a response
```

This proved that a response cannot bypass the analyst approval gate.

After approval:

```text
review_status = APPROVED
response_action = BLOCK_SOURCE_IP
response_status = PENDING
```

the simulated response executed successfully.

---

## 12. Analyst Dashboard

A new Next.js application was created at:

```text
dashboard/
```

Technology:

```text
Next.js
React
TypeScript
Tailwind CSS
```

The dashboard communicates with the existing FastAPI backend.

FastAPI CORS was configured for local development:

```text
http://localhost:3000
http://127.0.0.1:3000
```

---

## 13. Dashboard Home Screen

The main dashboard displays:

```text
Total Detections
ATTACK count
BENIGN count
Attack Rate
Recent Detections
Model
Confidence
Timestamp
Clickable incident records
```

### Validation evidence

![Sentinel analyst dashboard](assets/phase%208/01_analyst_dashboard.png)

This screen proves that the web application is consuming live FastAPI/PostgreSQL detection history.

---

## 14. Dynamic Incident Routing

Next.js dynamic routing was added using:

```text
app/incidents/[id]/page.tsx
```

Examples:

```text
/incidents/15
/incidents/18
```

The route reads the incident ID and requests:

```text
GET /detections/{id}
```

from FastAPI.

---

## 15. Full Incident Detail API

`GET /detections/{detection_id}` was expanded to return:

```text
ML detection
Network metadata
Threat intelligence
LLM analysis
Human review
Response state
```

This lets the dashboard display the complete incident lifecycle from one backend endpoint.

---

## 16. Incident Detail Screen

The incident screen displays:

```text
ML Detection
Network
Threat Intelligence
AI Incident Analysis
Severity
Reasoning
Risk Factors
Recommended Actions
Analyst Note
Human Review
Response
```

The specific Gemini model name remains stored in PostgreSQL for audit/debugging but is intentionally not emphasized in the analyst-facing UI.

---

## 17. Light and Dark Themes

The dashboard includes:

```text
Light mode
Dark mode
```

The selected theme is stored in browser `localStorage`.

The application applies the saved theme before rendering so the preferred appearance persists across refreshes.

Dark mode is the default presentation used for Sentinel documentation screenshots.

---

## 18. Human Decision Controls

When:

```text
attack == true
analysis_status == COMPLETED
review_status == PENDING
```

the incident page displays:

```text
Response Action
[ Block Source IP / Log Only ]

Analyst Note
[ text area ]

[ Reject Incident ] [ Approve Response ]
```

The dashboard directly calls the FastAPI review endpoint.

PowerShell is no longer required for normal analyst decisions.

---

## 19. Approved Response Controls

After approval:

```text
review_status = APPROVED
response_status = PENDING
```

the dashboard displays:

```text
Response approved
Authorized action: ...
[ Execute Approved Response ]
```

Clicking the button calls:

```text
POST /detections/{id}/respond
```

The incident page then reloads the fresh state from FastAPI.

---

## 20. Rejection Path Validation

A separate controlled incident was used to validate:

```text
PENDING
→ REJECTED
```

After rejection:

```text
review_status = REJECTED
response_action = NULL
response_status = NOT_STARTED
```

The dashboard displays:

```text
Incident rejected
No response action will be executed.
```

This proves both branches of the human decision layer.

---

## 21. Live AbuseIPDB + Gemini Validation

A clean controlled ATTACK shell was created with:

```text
threat_intelligence = NULL
incident_analysis = NULL
analysis_status = NOT_STARTED
```

It was then sent through the published n8n production workflow.

The live path was:

```text
Controlled ATTACK shell
        |
        v
n8n
        |
        v
AbuseIPDB LIVE
        |
        v
Save Threat Intelligence
        |
        v
FastAPI /analysis
        |
        v
Gemini LIVE
        |
        v
Save Structured Analysis
        |
        v
review_status = PENDING
        |
        v
Dashboard
```

Gemini generated:

```text
severity = LOW
```

based on the evidence available to it.

The controlled source IP was:

```text
8.8.8.8
```

and the live AbuseIPDB response showed:

```text
ISP: Google LLC
Whitelisted: Yes
Abuse Score: 0
```

The LLM therefore interpreted the conflicting evidence cautiously instead of automatically escalating the event.

### Validation evidence

![Live incident analysis](assets/phase%208/02_live_incident_analysis.png)

Important limitation:

The initial ATTACK state in this Phase 8 test was manually created. The live AbuseIPDB lookup, Gemini analysis, persistence, dashboard display, and human response were real, but this was not a genuine 77-feature XGBoost inference test.

A true:

```text
real attack feature row
→ /predict
→ XGBoost
→ n8n
→ AbuseIPDB
→ Gemini
→ dashboard
```

validation is reserved for Phase 10.

---

## 22. Browser-Based Human Response Validation

The live-analyzed incident was reviewed in the dashboard.

The analyst selected:

```text
LOG_ONLY
```

and approved the response.

The final state became:

```text
review_status = APPROVED
response_action = LOG_ONLY
response_status = EXECUTED
mode = SIMULATION
```

### Validation evidence

![Human response execution](assets/phase%208/03_human_response_execution.png)

This proves that the incident can move from live enrichment and AI analysis into a human-authorized response entirely through the web interface.

---

## 23. Phase 8 Security Boundaries

Phase 8 intentionally preserves these controls:

```text
LLM cannot directly execute response actions
Human approval is mandatory
Response actions are allowlisted
Approval and execution are separate steps
BENIGN detections cannot enter the response workflow
Completed responses cannot be executed twice
Response failures are persisted
```

The LLM remains advisory.

The human analyst remains the authority.

---

## 24. Files Added or Modified

Backend:

```text
backend/app/main.py
backend/app/models.py
backend/app/services/response_service.py
```

Dashboard:

```text
dashboard/app/page.tsx
dashboard/app/layout.tsx
dashboard/app/globals.css
dashboard/app/incidents/[id]/page.tsx
dashboard/components/ThemeToggle.tsx
dashboard/package.json
dashboard/next.config.ts
```

Automation:

```text
automation/sentinel_detection_automation.json
```

Documentation:

```text
docs/Sentinel_Phase_08_Analyst_Dashboard_Human_Approval_Response.md
docs/assets/phase 8/
README.MD
```

---

## 25. Major Concepts Learned

### Human-in-the-loop security

AI can recommend actions, but a human must authorize potentially disruptive responses.

### State machines

Review and response state are tracked independently.

### Frontend/backend separation

Next.js presents and operates the system while FastAPI remains the trusted backend.

### Dynamic routing

Each incident has a dedicated route:

```text
/incidents/{id}
```

### CORS

FastAPI explicitly allows the local dashboard origin during development.

### Response allowlists

Only explicitly implemented response actions can execute.

### Persistence

Human decisions and response outcomes are stored in PostgreSQL rather than existing only in the browser.

### Theme persistence

The dashboard remembers the user's light/dark preference through `localStorage`.

---

## 26. Phase 8 Outcome

Phase 8 is complete.

Sentinel now supports:

- a professional analyst dashboard
- live detection history
- ATTACK/BENIGN summary statistics
- clickable incident records
- full incident detail pages
- threat-intelligence visualization
- AI-analysis visualization
- AI-generated severity display
- human approval
- human rejection
- analyst notes
- response-action selection
- allowlisted response execution
- `BLOCK_SOURCE_IP` simulation
- `LOG_ONLY`
- persistent review state
- persistent response state
- response results
- light/dark mode
- browser-only analyst workflow
- live AbuseIPDB + Gemini validation

Sentinel has moved from automated detection and analysis into human-supervised incident response.

---

## 27. Transition to Phase 9

The next phase is:

```text
Phase 9 - Real-Time Detection + Live Monitoring & Analytics
```

The next evolution is:

```text
Static stored incidents
        |
        v
Real-time flow ingestion
        |
        v
Automatic inference
        |
        v
Live dashboard updates
        |
        v
Operational analytics
```

Planned Phase 9 work includes:

- real-time or near-real-time flow ingestion
- automatic XGBoost inference
- live incident feed
- dashboard auto-refresh or streaming updates
- attack/benign trend charts
- severity distribution
- top source IPs
- targeted ports
- service-health indicators
- operational monitoring
- dashboard analytics

Phase 10 will then perform genuine end-to-end traffic validation and deployment hardening.
