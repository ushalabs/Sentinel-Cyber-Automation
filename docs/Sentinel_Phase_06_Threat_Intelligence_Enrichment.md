# Sentinel — Phase 06: Threat Intelligence Enrichment

**Project:** Sentinel
**Phase:** 6 — Threat Intelligence Enrichment
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

The goal of Phase 6 was to attach real threat-intelligence context to suspicious network traffic without changing the trained XGBoost model or its 77-feature contract.

The completed architecture now supports:

- network metadata alongside ML features
- source/destination IP and port persistence
- AbuseIPDB source-IP reputation checks
- enriched incident generation inside n8n
- threat-intelligence write-back to PostgreSQL
- protection against attaching enrichment to BENIGN detections

---

## 2. Key Design Decision: ML Features vs Network Metadata

The XGBoost model was trained using exactly 77 numeric CIC-IDS2017 features.

Those features were intentionally left unchanged.

Network context was added separately through a metadata object:

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

This separation is important:

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

Metadata was made optional so older clients and the existing test script would continue to work.

Backward compatibility was verified successfully.

---

## 4. PostgreSQL Metadata Expansion

The existing `detections` table was expanded with six nullable columns:

```sql
ALTER TABLE detections
ADD COLUMN source_ip VARCHAR(45),
ADD COLUMN destination_ip VARCHAR(45),
ADD COLUMN source_port INTEGER,
ADD COLUMN destination_port INTEGER,
ADD COLUMN transport_protocol VARCHAR(20),
ADD COLUMN observed_at TIMESTAMPTZ;
```

`VARCHAR(45)` was used for IP addresses so both IPv4 and IPv6 can be supported.

`observed_at` represents when the network event was observed, while `created_at` represents when Sentinel stored the detection.

The SQLAlchemy `Detection` model was updated with matching nullable fields using SQLAlchemy 2 typed mappings.

Existing records remained valid and showed `NULL` for the new metadata fields.

---

## 5. Metadata Persistence

The `/predict` route was updated so incoming metadata is stored with each detection.

Conceptually:

```python
source_ip=request.metadata.source_ip if request.metadata else None
```

The same approach was used for destination IP, source/destination ports, protocol, and observed time.

A test prediction containing metadata successfully created a PostgreSQL record containing:

```text
source_ip          203.0.113.50
destination_ip     192.168.1.10
source_port        51542
destination_port   22
transport_protocol TCP
observed_at         2026-09-20 13:05:00+05
```

---

## 6. FastAPI to n8n Metadata Transport

`backend/app/services/automation.py` was extended so the n8n webhook receives both the prediction result and the network metadata.

The automation payload now includes:

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

The datetime is converted using `isoformat()` before being sent as JSON.

A production-style n8n execution confirmed that the complete metadata object arrived successfully.

---

## 7. Threat Intelligence Provider

AbuseIPDB was selected as the first threat-intelligence provider for Sentinel.

The API key is stored using n8n Credentials rather than hardcoded into source code or the exported workflow.

The n8n HTTP Request node is named:

```text
Check Source IP Reputation
```

It performs:

```text
GET https://api.abuseipdb.com/api/v2/check
```

with:

```text
ipAddress    = source_ip
maxAgeInDays = 90
verbose      = true
```

and:

```text
Accept: application/json
```

The API key is sent securely through the configured n8n Header Auth credential.

---

## 8. Updated n8n ATTACK Branch

The ATTACK path became:

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

The BENIGN path remains:

```text
Webhook
   |
   v
IF attack == false
   |
   v
Prepare Benign Result
   |
   v
Respond to Webhook (Benign)
```

Only ATTACK events perform the AbuseIPDB lookup.

---

## 9. Enriched Incident Object

The `Prepare Attack Alert` node combines two data sources:

1. original Sentinel detection data from the Webhook node
2. AbuseIPDB threat-intelligence output

Original event values are referenced from:

```text
$('Webhook').item.json.body...
```

Threat-intelligence values are read from:

```text
$json.data...
```

The resulting enriched object contains:

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

This was the first complete enrichment stage in Sentinel.

---

## 10. AbuseIPDB Validation

A controlled test event used the public IP:

```text
8.8.8.8
```

This was used only to validate the integration and was not treated as a real attacker.

The returned AbuseIPDB data included:

```text
IP Address              8.8.8.8
Public                   true
IP Version               4
Whitelisted              true
Abuse Confidence Score   0
Country                  United States of America
ISP                      Google LLC
Domain                   google.com
Usage Type               Content Delivery Network
Total Reports            203
```

This test also demonstrated an important security-analysis concept:

> The number of historical reports alone should not be treated as proof that an IP is malicious.

The returned whitelist status and abuse confidence score provide important additional context.

---

## 11. Threat-Intelligence Persistence Design

Instead of creating a database column for every AbuseIPDB property, Sentinel stores provider-specific intelligence as JSONB.

Three columns were added:

```sql
ALTER TABLE detections
ADD COLUMN threat_provider VARCHAR(50),
ADD COLUMN threat_intelligence JSONB,
ADD COLUMN enriched_at TIMESTAMPTZ;
```

This design avoids tightly coupling Sentinel to a single threat-intelligence provider.

Conceptually:

```text
Detection
├── ML Result
├── Network Metadata
└── Threat Intelligence
    ├── threat_provider
    ├── threat_intelligence JSONB
    └── enriched_at
```

Future providers such as VirusTotal or OTX can use the same architecture without requiring a database redesign.

---

## 12. Threat Enrichment API

A new request schema was added:

```python
class ThreatEnrichmentRequest(BaseModel):
    threat_provider: str
    threat_intelligence: dict
```

A new FastAPI endpoint was created:

```text
POST /detections/{detection_id}/enrichment
```

Its responsibilities are:

1. locate the requested detection
2. reject missing detections with `404`
3. reject BENIGN detections with `400`
4. save the threat provider
5. save the threat-intelligence JSON
6. store the enrichment timestamp
7. commit the PostgreSQL transaction

The endpoint returns the saved enrichment record after success.

---

## 13. BENIGN Safety Guard

A safety rule was added:

```python
if not detection.attack:
    raise HTTPException(
        status_code=400,
        detail="Threat intelligence enrichment is only allowed for ATTACK detections"
    )
```

This prevents threat intelligence from being accidentally attached to benign records.

The guard was explicitly tested against a known BENIGN detection.

Expected result:

```text
400 Bad Request
```

with:

```json
{
  "detail": "Threat intelligence enrichment is only allowed for ATTACK detections"
}
```

The test passed.

---

## 14. n8n Write-Back to FastAPI

A new n8n HTTP Request node was added:

```text
Save Threat Intelligence
```

It calls:

```text
POST http://127.0.0.1:8000/detections/{detection_id}/enrichment
```

with:

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

This completed the circular pipeline:

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

---

## 15. Rich Webhook Response

After adding the database write-back node, the attack webhook initially returned only the FastAPI persistence response.

The Respond to Webhook node was therefore changed to return the output of:

```text
Prepare Attack Alert
```

using:

```text
{{ $('Prepare Attack Alert').item.json }}
```

This allows Sentinel to:

1. save the threat intelligence to PostgreSQL
2. still return the full enriched CRITICAL incident to the caller

A successful response contained:

```text
status                  CRITICAL
detection_id            9
model                   XGBoost
confidence              0.99
source_ip               8.8.8.8
destination_ip          192.168.1.10
source_port             51542
destination_port        22
transport_protocol      TCP
abuse_confidence_score  0
is_whitelisted          True
country                 United States of America
isp                     Google LLC
domain                  google.com
usage_type              Content Delivery Network
total_reports           203
```

---

## 16. Production Validation

A controlled ATTACK database record was created specifically for integration validation.

It was not presented as a real model detection.

The record used:

```text
prediction          ATTACK
attack              true
confidence          0.99
source_ip           8.8.8.8
destination_ip      192.168.1.10
source_port         51542
destination_port    22
transport_protocol  TCP
```

The published production webhook was then called:

```text
POST http://localhost:5678/webhook/sentinel-detection
```

The complete ATTACK branch executed successfully.

PostgreSQL confirmed that the same ATTACK record was updated with:

```text
threat_provider      AbuseIPDB
threat_intelligence  populated JSONB
enriched_at          populated timestamp
```

The temporary controlled ATTACK record was deleted after validation.

---

## 17. BENIGN Regression Test

The original model-serving test was run again after all Phase 6 changes.

Result:

```text
prediction             BENIGN
attack                 false
automation_triggered   true
automation_result      SAFE
```

n8n correctly executed only:

```text
Webhook
   |
   v
IF
   |
   v FALSE
Prepare Benign Result
   |
   v
Respond to Webhook (Benign)
```

The AbuseIPDB and threat-intelligence persistence nodes did not execute.

PostgreSQL confirmed:

```text
threat_provider      NULL
threat_intelligence  NULL
enriched_at          NULL
```

for the new BENIGN detection.

This confirmed that Phase 6 did not break the Phase 1–5 BENIGN pipeline.

---

## 18. Final Phase 6 Architecture

```text
                         Sentinel Phase 6

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

## 19. Files Modified in Phase 6

Main backend changes:

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

Database:

```text
detections table expanded with network metadata and threat-intelligence persistence
```

Documentation:

```text
docs/Sentinel_Phase_06_Threat_Intelligence_Enrichment.md
```

---

## 20. Major Concepts Learned

Phase 6 introduced several important backend and cybersecurity concepts:

### Optional Types

```python
str | None
```

A value can contain a string or be absent.

### Conditional Expressions

```python
value if condition else None
```

Used to safely handle optional metadata.

### Named Function Arguments

```python
send_detection_to_n8n(
    source_ip=detection.source_ip,
    ...
)
```

Makes larger function calls easier to understand and safer to maintain.

### JSONB

PostgreSQL JSONB allows flexible structured threat-intelligence data without requiring a separate database column for every provider field.

### HTTP APIs

Sentinel now performs both:

```text
GET  -> query external threat intelligence
POST -> persist enrichment back into FastAPI
```

### Data Enrichment

Data enrichment combines an original event with additional external context.

### Defensive Validation

The enrichment endpoint validates that only ATTACK detections can receive threat-intelligence data.

### Separation of Concerns

ML features, network metadata, automation data, and threat intelligence are kept logically separate.

---

## 21. Issues Encountered

### Swagger Feature Placeholders

Because prediction features use:

```python
dict[str, float]
```

Swagger displays generic `additionalProp` fields instead of all 77 feature names.

This does not affect model inference.

### Python Syntax / Indentation Errors

Minor syntax issues occurred while extending the detection model and enrichment endpoint, including:

- a missing comma
- incorrect indentation under an `if` statement

These were corrected and FastAPI reloaded successfully.

### Test vs Production n8n Webhooks

n8n uses different routes:

```text
/webhook-test/...
```

for editor test executions and:

```text
/webhook/...
```

for published production executions.

Using the production URL while testing an unpublished draft initially executed the older workflow version.

### Workflow Data Context

After the HTTP Request node, `$json` referred to the AbuseIPDB response rather than the original webhook body.

The original detection data was therefore accessed explicitly with:

```text
$('Webhook').item.json.body...
```

### Write-Back Response Replaced Rich Alert

Adding the persistence node caused the final webhook to return the database-save response.

The Respond to Webhook node was changed to return:

```text
$('Prepare Attack Alert').item.json
```

instead.

---

## 22. Phase 6 Outcome

Phase 6 is complete.

Sentinel now supports:

- network metadata alongside the 77-feature ML payload
- source/destination IP tracking
- source/destination port tracking
- protocol and observation timestamp persistence
- ATTACK-only external IP reputation checks
- AbuseIPDB integration
- enriched security incidents
- threat-intelligence JSONB persistence
- threat-provider tracking
- enrichment timestamps
- a dedicated enrichment API endpoint
- protection against enriching BENIGN detections
- a validated production n8n workflow
- BENIGN regression compatibility

Sentinel has therefore moved beyond pure ML classification into an actual security automation and enrichment pipeline.

---

## 23. Transition to Phase 7

The next phase is:

```text
Phase 7 — LLM Incident Analysis
```

Phase 7 will use the richer incident data produced by Phase 6 so an LLM can reason over information such as:

```text
ML prediction
confidence
source/destination context
ports
protocol
AbuseIPDB reputation
ISP
country
domain
report history
```

Instead of receiving only:

```text
ATTACK — 99% confidence
```

the analysis layer will receive a structured incident with technical context.

This creates the foundation for later:

```text
Phase 8 — Human Approval & Automated Response
Phase 9 — Real-Time Detection System & Dashboard
Phase 10 — Full Validation & Deployment Readiness
```
