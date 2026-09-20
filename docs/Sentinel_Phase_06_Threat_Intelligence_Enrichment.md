# Sentinel - Phase 06: Threat Intelligence Enrichment

**Project:** Sentinel
**Phase:** 6 - Threat Intelligence Enrichment
**Status:** Complete
**Completed:** September 2026

---

## 1. Objective

Phase 6 extended Sentinel from a machine-learning intrusion detector into a threat-enrichment pipeline.

Before this phase, Sentinel could:

- receive 77 CIC-IDS2017 flow features
- classify traffic as `BENIGN` or `ATTACK`
- store detections in PostgreSQL
- trigger an n8n workflow
- route ATTACK and BENIGN events into separate automation branches

The goal of Phase 6 was to attach external threat-intelligence context to suspicious network traffic without changing the trained XGBoost model or its 77-feature contract.

The completed phase adds:

- network metadata beside the ML feature vector
- source/destination IP and port persistence
- AbuseIPDB source-IP reputation checks
- enriched incident generation in n8n
- threat-intelligence write-back to PostgreSQL
- a guard that prevents enrichment of BENIGN detections

---

## 2. Key Design Decision: ML Features vs Network Metadata

The production model still receives exactly 77 numeric features.

Network identifiers are carried separately:

```json
{
  "features": {
    "...": 0
  },
  "metadata": {
    "source_ip": "203.0.113.50",
    "destination_ip": "192.168.1.10",
    "source_port": 51542,
    "destination_port": 22,
    "transport_protocol": "TCP",
    "observed_at": "2026-09-20T13:05:00+05:00"
  }
}
```

Conceptually:

```text
77 ML Features
    |
    v
XGBoost

Network Metadata
    |
    +--> PostgreSQL
    +--> n8n
    +--> Threat Intelligence
    +--> Future Dashboard / Incident Analysis
```

The IP addresses and ports are not fed into XGBoost.

---

## 3. FastAPI Request Schema Upgrade

A new Pydantic model was added:

```python
class NetworkMetadata(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    transport_protocol: str | None = None
    observed_at: datetime | None = None
```

The prediction request became:

```python
class PredictionRequest(BaseModel):
    features: dict[str, float]
    metadata: NetworkMetadata | None = None
```

Metadata is optional so existing clients remain compatible.

---

## 4. PostgreSQL Metadata Expansion

The `detections` table was expanded with six nullable columns:

```sql
ALTER TABLE detections
ADD COLUMN source_ip VARCHAR(45),
ADD COLUMN destination_ip VARCHAR(45),
ADD COLUMN source_port INTEGER,
ADD COLUMN destination_port INTEGER,
ADD COLUMN transport_protocol VARCHAR(20),
ADD COLUMN observed_at TIMESTAMPTZ;
```

`VARCHAR(45)` supports both IPv4 and IPv6 text representations.

`observed_at` represents when the network event was observed, while `created_at` represents when Sentinel stored the detection.

### Validation evidence

The metadata test record stored all six new values successfully:

![Network metadata persisted in PostgreSQL](assets/phase-06/01_metadata_persistence.png)

---

## 5. Metadata Persistence in `/predict`

The `/predict` route now stores incoming metadata with the detection.

Example:

```python
source_ip=request.metadata.source_ip if request.metadata else None
```

The same pattern is used for destination IP, ports, protocol, and observation time.

This keeps metadata optional while allowing richer detections when a real network collector is added later.

---

## 6. FastAPI to n8n Metadata Transport

`backend/app/services/automation.py` was extended so n8n receives:

```text
detection_id
prediction
attack
confidence
model
source_ip
destination_ip
source_port
destination_port
transport_protocol
observed_at
```

The observation timestamp is serialized with `isoformat()` before being sent as JSON.

---

## 7. Threat Intelligence Provider

AbuseIPDB was selected as Sentinel's first threat-intelligence provider.

The API key is stored in n8n Credentials rather than hardcoded into source code or the exported workflow.

The n8n HTTP Request node is named:

```text
Check Source IP Reputation
```

It performs a lookup using the source IP and returns reputation context such as:

```text
abuseConfidenceScore
isWhitelisted
countryName
isp
domain
usageType
totalReports
lastReportedAt
```

---

## 8. Updated n8n ATTACK Branch

The ATTACK branch now performs threat-intelligence enrichment before responding:

```text
Webhook
   |
   v
IF attack == true?
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
Respond to Webhook (Attack)
```

The BENIGN branch remains separate and does not call AbuseIPDB.

### Validation evidence

The published ATTACK workflow completed through the enrichment and persistence nodes:

![Published n8n ATTACK enrichment workflow](assets/phase-06/02_attack_workflow.png)

---

## 9. Enriched Incident Object

`Prepare Attack Alert` combines two sources:

1. the original Sentinel webhook event
2. the current AbuseIPDB response

Original event values are referenced with:

```text
$('Webhook').item.json.body...
```

Threat-intelligence values are read from:

```text
$json.data...
```

The enriched incident contains:

```text
status
message
detection_id
model
confidence
source_ip
destination_ip
source_port
destination_port
transport_protocol
observed_at
abuse_confidence_score
is_whitelisted
country
isp
domain
usage_type
total_reports
last_reported_at
```

### Validation evidence

A controlled ATTACK integration test returned the full enriched incident:

![Enriched CRITICAL webhook response](assets/phase-06/03_enriched_attack_response.png)

The test used `8.8.8.8` only as a public-IP integration target. The returned reputation showed a whitelist result and an abuse confidence score of 0, so Sentinel was not treating Google DNS itself as a real attacker. The `CRITICAL` state came from the intentionally fabricated ATTACK event used to validate the pipeline.

---

## 10. Threat-Intelligence Persistence Design

Instead of creating one SQL column for every provider property, provider-specific enrichment is stored as JSONB.

Three columns were added:

```sql
ALTER TABLE detections
ADD COLUMN threat_provider VARCHAR(50),
ADD COLUMN threat_intelligence JSONB,
ADD COLUMN enriched_at TIMESTAMPTZ;
```

Conceptually:

```text
Detection
|-- ML Result
|-- Network Metadata
`-- Threat Intelligence
    |-- threat_provider
    |-- threat_intelligence JSONB
    `-- enriched_at
```

This allows future threat-intelligence providers to use the same persistence structure without another database redesign.

---

## 11. Threat Enrichment API

A new request schema was added:

```python
class ThreatEnrichmentRequest(BaseModel):
    threat_provider: str
    threat_intelligence: dict
```

A new endpoint was created:

```text
POST /detections/{detection_id}/enrichment
```

The endpoint:

1. locates the detection
2. returns `404` if it does not exist
3. rejects BENIGN detections
4. saves the provider name
5. saves the enrichment JSONB
6. stores an enrichment timestamp
7. commits the update

---

## 12. BENIGN Safety Guard

The enrichment endpoint includes:

```python
if not detection.attack:
    raise HTTPException(
        status_code=400,
        detail="Threat intelligence enrichment is only allowed for ATTACK detections"
    )
```

This prevents accidental threat enrichment of benign records.

### Validation evidence

The guard correctly rejected an enrichment request for a BENIGN detection:

![BENIGN enrichment guard returning 400](assets/phase-06/05_benign_guard.png)

---

## 13. n8n Write-Back to FastAPI

A new n8n node named:

```text
Save Threat Intelligence
```

calls:

```text
POST http://127.0.0.1:8000/detections/{detection_id}/enrichment
```

with a body similar to:

```json
{
  "threat_provider": "AbuseIPDB",
  "threat_intelligence": {
    "abuse_confidence_score": 0,
    "is_whitelisted": true,
    "country": "United States of America",
    "isp": "Google LLC",
    "domain": "google.com",
    "usage_type": "Content Delivery Network",
    "total_reports": 203,
    "last_reported_at": "2026-09-19T11:22:54+00:00"
  }
}
```

This completes the circular pipeline:

```text
FastAPI
   |
   v
PostgreSQL
   |
   v
n8n
   |
   v
AbuseIPDB
   |
   v
n8n Enrichment
   |
   v
FastAPI Enrichment Endpoint
   |
   v
PostgreSQL Update
```

### Validation evidence

The controlled ATTACK row was updated with `AbuseIPDB`, a populated JSONB object, and an enrichment timestamp:

![Threat intelligence written back to PostgreSQL](assets/phase-06/04_postgres_enrichment_writeback.png)

---

## 14. Rich Webhook Response

After introducing the persistence node, the final webhook initially returned only the database-save response.

`Respond to Webhook (Attack)` was changed to return:

```text
{{ $('Prepare Attack Alert').item.json }}
```

This allows the workflow to save enrichment first while still returning the complete CRITICAL incident to the caller.

---

## 15. Production Validation

A controlled ATTACK database row was created specifically for integration testing.

It was not presented as a real model detection.

The published production endpoint was then called:

```text
POST /webhook/sentinel-detection
```

The production ATTACK flow completed successfully:

```text
Published n8n workflow
        |
        v
AbuseIPDB
        |
        v
Prepare enriched incident
        |
        v
FastAPI enrichment endpoint
        |
        v
PostgreSQL update
        |
        v
Rich CRITICAL response
```

After validation, the temporary ATTACK record was deleted.

---

## 16. BENIGN Regression Test

The original prediction test was run again after all Phase 6 changes.

The model returned:

```text
prediction             BENIGN
attack                 false
automation_triggered   true
automation_result      SAFE
```

The n8n execution followed only the BENIGN branch.

### Validation evidence

The AbuseIPDB and persistence nodes were not executed:

![BENIGN workflow bypasses threat enrichment](assets/phase-06/06_benign_workflow.png)

The newest BENIGN database row also contained no threat enrichment:

![BENIGN detection has no threat intelligence](assets/phase-06/07_benign_database.png)

This confirms that Phase 6 did not break the existing BENIGN pipeline.

---

## 17. Final Phase 6 Architecture

```text
                    Network Flow / Event
                            |
                  +---------+---------+
                  |                   |
                  v                   v
            77 ML Features       Network Metadata
                  |             src/dst IP, ports,
                  |             protocol, timestamp
                  |                   |
                  +---------+---------+
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
                     attack == true?
                       /         \
                     NO           YES
                     |             |
                     v             v
                  SAFE      AbuseIPDB Lookup
                                   |
                                   v
                         Enriched Incident
                                   |
                                   v
                         Save Enrichment
                                   |
                                   v
                              FastAPI
                                   |
                                   v
                              PostgreSQL
                                   |
                                   v
                       Rich CRITICAL Response
```

---

## 18. Files Modified in Phase 6

Backend:

```text
backend/app/main.py
backend/app/models.py
backend/app/services/automation.py
backend/test_prediction.py
```

Automation:

```text
automation/sentinel_detection_automation.json
```

Documentation:

```text
docs/Sentinel_Phase_06_Threat_Intelligence_Enrichment.md
docs/assets/phase-06/
```

---

## 19. Major Concepts Learned

### Optional Types

```python
str | None
```

A value may contain a string or be absent.

### Conditional Expressions

```python
value if condition else None
```

Used to safely handle optional metadata.

### Named Function Arguments

Named arguments make larger function calls easier to read and harder to mix up.

### JSONB

PostgreSQL JSONB stores structured provider-specific data without requiring one SQL column per property.

### HTTP APIs

Sentinel now uses both:

```text
GET  -> query external threat intelligence
POST -> persist enrichment back into FastAPI
```

### Data Enrichment

The original detection is combined with external reputation context.

### Defensive Validation

The enrichment endpoint refuses to enrich BENIGN detections.

### Separation of Concerns

ML features, network metadata, automation data, and threat intelligence remain logically separate.

---

## 20. Issues Encountered

### Swagger feature placeholders

Because features are defined as:

```python
dict[str, float]
```

Swagger shows generic property placeholders rather than all 77 feature names.

This does not affect inference.

### Python syntax and indentation

Small syntax issues were encountered during development, including a missing comma and an indentation error. Both were corrected and Uvicorn reloaded normally.

### n8n test vs production webhooks

n8n uses:

```text
/webhook-test/...
```

for editor testing and:

```text
/webhook/...
```

for published production execution.

Using the production URL before publishing the updated draft initially executed the older workflow version.

### Workflow data context

After the AbuseIPDB HTTP Request node, `$json` referred to the AbuseIPDB response rather than the original webhook body.

The original detection data was therefore referenced explicitly through the `Webhook` node.

### Persistence node changed the response

Adding `Save Threat Intelligence` caused the final webhook to return the persistence response. The Respond node was adjusted to return the earlier enriched incident instead.

---

## 21. Phase 6 Outcome

Phase 6 is complete.

Sentinel now supports:

- network metadata alongside the 77-feature ML payload
- source/destination IP tracking
- source/destination port tracking
- protocol and observation timestamp persistence
- ATTACK-only source-IP reputation checks
- AbuseIPDB integration
- enriched security incidents
- threat-intelligence JSONB persistence
- threat-provider tracking
- enrichment timestamps
- a dedicated enrichment API endpoint
- protection against enriching BENIGN detections
- a validated published n8n workflow
- BENIGN regression compatibility

Sentinel has moved beyond pure ML classification into a security automation and threat-enrichment pipeline.

---

## 22. Transition to Phase 7

The next phase is:

```text
Phase 7 - LLM Incident Analysis
```

Phase 7 will use the enriched incident object as context for LLM-assisted analysis, including:

```text
ML prediction
confidence
network metadata
source IP reputation
country
ISP
domain
report history
```

This creates the foundation for later human approval and automated response workflows.
