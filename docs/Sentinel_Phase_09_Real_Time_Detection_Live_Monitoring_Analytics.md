# Sentinel - Phase 09: Real-Time Detection, Live Monitoring & Advanced Analytics

**Project:** Sentinel
**Phase:** 9 - Real-Time Detection, Live Monitoring & Advanced Analytics
**Status:** Complete
**Completed:** September 2026

---

## 1. Objective

Phase 9 moves Sentinel from request-driven testing into a live network monitoring prototype.

Before this phase, Sentinel already supported:

- XGBoost intrusion classification
- FastAPI model serving
- PostgreSQL persistence
- n8n automation
- AbuseIPDB threat enrichment
- Gemini incident analysis
- a Next.js analyst dashboard
- human approval and rejection
- allowlisted response execution

Phase 9 adds the operational layer required for continuous monitoring:

- a separate live network Collector process
- Windows packet capture through Npcap + Scapy
- bidirectional flow construction
- CICFlow-style 77-feature extraction
- automatic XGBoost inference from captured traffic
- live WebSocket events
- dashboard auto-updates without manual refresh
- live detection analytics
- service-health monitoring
- Collector heartbeat/status reporting
- attack-focused n8n routing
- a persistent Analyst Queue for incidents requiring human attention
- controlled replay of genuine CIC-IDS2017 ATTACK samples
- full ATTACK-path validation through XGBoost, n8n, AbuseIPDB, Gemini, and human review

---

## 2. Final Phase 9 Architecture

```text
                    LIVE NETWORK TRAFFIC
                            |
                            v
                    Windows Ethernet
                            |
                            v
                      Npcap + Scapy
                            |
                            v
                    Sentinel Collector
                            |
                  +---------+---------+
                  |                   |
                  v                   v
             Flow grouping       Heartbeat
                  |                   |
                  v                   v
         CICFlow-style 77        FastAPI
             features          /collector/heartbeat
                  |                   |
                  v                   v
               /predict        /system/status
                  |
                  v
               XGBoost
                  |
          +-------+-------+
          |               |
          v               v
       BENIGN           ATTACK
          |               |
          v               v
     PostgreSQL      PostgreSQL
          |               |
          v               v
     WebSocket          n8n
          |               |
          v               v
      Dashboard       AbuseIPDB
                          |
                          v
                 Save Threat Intelligence
                          |
                          v
                    Gemini Analysis
                          |
                          v
                   review_status=PENDING
                          |
                          v
                    Analyst Queue
                          |
                          v
                   Human Review
                    /         \
               REJECT       APPROVE
                              |
                              v
                    Allowlisted Response
```

The model contract remains exactly:

```text
77 numeric network-flow features
```

Network metadata, automation, threat intelligence, LLM analysis, review state, and response state remain separate from the ML feature vector.

---

## 3. Collector Service

A new independent Collector process was added under:

```text
collector/
```

The Collector is responsible for:

```text
Live packet capture
→ bidirectional flow grouping
→ CICFlow-style feature extraction
→ /predict submission
→ heartbeat reporting
```

The Collector does not contain XGBoost itself. FastAPI remains the trusted inference service.

This preserves a clean service boundary:

```text
Collector = observe + transform
FastAPI   = validate + classify + persist + route
```

---

## 4. Windows Packet Capture

Phase 9 uses:

```text
Npcap
Scapy
```

to capture real IPv4 TCP and UDP traffic from the active Windows Ethernet adapter.

During development, the active interface was identified as:

```text
Ethernet
Realtek Gaming GbE Family Controller
```

The first live capture validation proved that Python could observe real inbound and outbound traffic rather than synthetic packets.

---

## 5. Flow Grouping

The XGBoost model is flow-based, not packet-based.

Raw packet output was therefore replaced with bidirectional flow aggregation.

A flow groups packets by:

```text
Protocol
Source IP
Source Port
Destination IP
Destination Port
Reverse direction
```

The first observed packet defines the forward direction.

Instead of:

```text
packet
packet
packet
packet
...
```

Sentinel now reasons about:

```text
192.168.100.3:port
        <->
remote_host:port

Protocol
Duration
Forward packets
Backward packets
Forward bytes
Backward bytes
Timing statistics
TCP flags
Window information
```

---

## 6. Exact 77-Feature Contract

The production model contract is stored in:

```text
ML Models/XGBoost/sentinel_feature_columns_v1.joblib
```

Phase 9 verified that the saved contract contains exactly 77 features.

The extractor now produces the complete ordered vector, including:

```text
Protocol
Flow Duration
Forward / backward packet counts
Forward / backward packet-length statistics
Flow Bytes/s
Flow Packets/s
Flow IAT statistics
Forward IAT statistics
Backward IAT statistics
PSH / URG directional flags
Header lengths
Packet rates
Packet-length statistics
TCP flag counts
Down/Up Ratio
Average segment sizes
Bulk statistics
Subflow statistics
Initial TCP window sizes
Forward active-data packets
Forward segment-size minimum
Active statistics
Idle statistics
```

Before inference, the Collector verifies:

```text
77/77 features
correct order
finite numeric values
```

A malformed vector is rejected instead of silently reaching XGBoost.

---

## 7. CICFlowMeter Source Alignment

The feature extractor was aligned against the CICFlowMeter implementation used by the CIC-IDS2017 ecosystem.

Phase 9 specifically accounted for behavior around:

- protocol values (`6` TCP, `17` UDP)
- microsecond timing
- forward direction
- payload-based packet-length statistics
- transport header length
- flow IAT calculations
- forward/backward IAT calculations
- TCP flag counts
- active/idle timing
- subflow behavior
- bulk behavior
- initial window fields
- forward active-data packets
- the saved `CWE Flag Count` naming corresponding to CWR behavior

The live prototype uses a shorter inactivity flush to produce operational results quickly, while Phase 10 is reserved for stricter replay/parity validation against the training-generation behavior.

---

## 8. Automatic Live Inference

Completed live flows are automatically sent to:

```text
POST /predict
```

The pipeline is:

```text
CAPTURE
→ FLOW
→ 77 FEATURES
→ /predict
→ XGBoost
→ PostgreSQL
→ WebSocket
```

The live Collector successfully generated real BENIGN detections from normal network traffic.

Each result receives a normal PostgreSQL detection ID and appears in the dashboard automatically.

---

## 9. ATTACK-Only Automation Routing

Earlier phases sent both ATTACK and BENIGN events to n8n and used an n8n `If` node for routing.

Phase 9 simplified the responsibility boundary.

The backend now uses:

```text
BENIGN
→ persist
→ dashboard
→ stop

ATTACK
→ persist
→ dashboard
→ n8n
```

The final n8n workflow therefore handles only ATTACK incidents.

This removes duplicate classification logic from n8n and gives each service one clear responsibility:

```text
XGBoost / FastAPI = detection and routing decision
n8n               = attack enrichment and orchestration
Gemini            = incident analysis
Human analyst     = final response decision
```

---

## 10. Final n8n Workflow

The published Phase 9 workflow is:

```text
Webhook
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
Respond to Webhook
```

The old BENIGN branch is no longer required in the production workflow.

### Evidence

![Finalized n8n attack-only workflow](assets/phase%209/Finalized%20n8n%20structure.png)

---

## 11. WebSocket Live Event Layer

A WebSocket endpoint was added:

```text
/ws/events
```

The backend broadcasts operational events such as:

```text
DETECTION_CREATED
THREAT_INTELLIGENCE_UPDATED
ANALYSIS_COMPLETED
REVIEW_UPDATED
RESPONSE_UPDATED
```

The dashboard listens for these events and refreshes the relevant state automatically.

This means new detections can appear without a manual browser refresh.

---

## 12. Live Incident Page Updates

Incident detail pages also subscribe to the live event channel.

A detail page refreshes itself when the current incident receives:

```text
THREAT_INTELLIGENCE_UPDATED
ANALYSIS_COMPLETED
REVIEW_UPDATED
RESPONSE_UPDATED
```

This allows the analyst to watch an ATTACK progress through enrichment, Gemini analysis, and human review state.

---

## 13. Dashboard Analytics

Phase 9 expanded the dashboard from a detection list into an operational SOC-style view.

New statistics include:

```text
Total Detections
Attacks
Benign
Attack Rate
Pending Review
Critical Incidents
```

The dashboard also contains:

```text
24-hour Detection Activity
Severity Distribution
Top Targeted Ports
Top Source IPs
System Status
Recent Detections
Analyst Queue
```

---

## 14. Detection Activity Visualization

A new endpoint provides hourly activity:

```text
GET /dashboard/activity?hours=24
```

The initial line-chart approach was replaced with stacked hourly bars because zero-level ATTACK lines could visually imply continued attack activity.

The final chart uses:

```text
Red   = ATTACK
Green = BENIGN
```

Hours with no events render no bar.

The y-axis scales dynamically with the largest hourly count.

---

## 15. Severity Distribution

A new endpoint provides ATTACK severity counts:

```text
GET /dashboard/severity
```

The dashboard groups analyzed incidents into:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Severity comes from the persisted Gemini incident analysis.

---

## 16. Top Targeted Ports

A new endpoint provides the most common destination ports among ATTACK detections:

```text
GET /dashboard/top-ports
```

This is a frequency view over stored ATTACK records.

It does not independently claim that a port is malicious.

---

## 17. Top Source IPs

A new endpoint provides the most frequent source IPs among ATTACK detections:

```text
GET /dashboard/top-sources
```

This helps an analyst identify repeated sources across stored ATTACK classifications.

---

## 18. System Health Monitoring

A new health endpoint was added:

```text
GET /system/status
```

It reports:

```json
{
  "api": "ONLINE",
  "database": "ONLINE",
  "model": "LOADED",
  "n8n": "ONLINE",
  "collector": "RUNNING"
}
```

The dashboard displays status cards for:

```text
FastAPI
PostgreSQL
XGBoost
n8n
Collector
```

---

## 19. Collector Heartbeat

The Collector sends periodic heartbeats to:

```text
POST /collector/heartbeat
```

The backend distinguishes:

```text
No heartbeat ever
→ NOT_STARTED

Recent heartbeat
→ RUNNING

Heartbeat previously seen but stale
→ OFFLINE
```

The dashboard polls system health periodically so Collector state changes do not require a page reload.

`RUNNING` is treated as a healthy green state.

---

## 20. Analyst Queue

Continuous live traffic creates many BENIGN rows, so an ATTACK could quickly move down the normal Recent Detections list.

Phase 9 adds a dedicated sticky Analyst Queue.

Endpoint:

```text
GET /dashboard/attention
```

The queue contains actionable ATTACK incidents and shows states such as:

```text
ANALYZING
PENDING REVIEW
ANALYSIS FAILED
```

The queue displays:

```text
Incident ID
Source IP / port
ATTACK badge
Analysis / review state
Severity
Confidence
Protocol
Link to incident
```

The queue stays pinned while the analyst scrolls.

At the top of the dashboard it starts aligned with the dashboard statistic cards. As the user scrolls down, it becomes sticky near the top of the viewport.

An incident leaves the queue after the analyst reviews it.

Historical ATTACK test rows without actionable metadata are excluded from the queue rather than deleted from PostgreSQL.

### Evidence

![Phase 9 dashboard with Analyst Queue](assets/phase%209/New%20Dashboard.png)

---

## 21. Genuine ATTACK Replay

The local CIC-IDS2017 dataset is stored as Parquet files.

A replay utility was added to select a genuine labeled ATTACK row from files such as:

```text
Dataset/CIC-IDS2017/DDoS-Friday-no-metadata.parquet
```

The replay utility:

```text
loads the Parquet file
→ finds a finite ATTACK row
→ maps it to the exact 77 saved features
→ sends it through /predict
→ enables ATTACK automation
```

This avoids inventing synthetic attack feature values.

---

## 22. DDoS XGBoost Validation

A genuine DDoS row was replayed.

Result:

```text
Dataset label         : DDoS
XGBoost prediction    : ATTACK
Confidence            : ~0.999999
Attack probability    : ~0.999999
```

This confirmed that a genuine CIC-IDS2017 ATTACK feature vector still follows the saved production model contract and is classified as ATTACK.

---

## 23. Full ATTACK Automation Validation

After XGBoost validation, the same controlled replay path was used with automation enabled.

Because the `no-metadata` Parquet file does not contain source/destination network metadata, controlled metadata was supplied for the automation layer.

The ML evidence remained genuine CIC-IDS2017 DDoS features.

The validated path was:

```text
Genuine CIC-IDS2017 DDoS features
        |
        v
FastAPI /predict
        |
        v
XGBoost = ATTACK
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
Save Threat Intelligence
        |
        v
Gemini
        |
        v
analysis_status = COMPLETED
        |
        v
review_status = PENDING
        |
        v
Analyst Queue
```

Observed result:

```text
Threat provider       : AbuseIPDB
Enriched              : True
Analysis status       : COMPLETED
LLM provider          : Google Gemini
Severity              : LOW
Review status         : PENDING
```

The LOW severity was reasonable for the controlled metadata used in the test and should not be interpreted as the DDoS dataset row itself having low severity.

### Evidence

![Controlled genuine DDoS replay through the full Sentinel attack pipeline](assets/phase%209/Complete%20Architecture%20flow.png)

---

## 24. Important Validation Boundary

Phase 9 proves two different things:

### Live benign path

```text
real captured Windows traffic
→ Collector
→ live flow
→ 77 extracted features
→ XGBoost
→ BENIGN
→ PostgreSQL
→ WebSocket
→ Dashboard
```

### Genuine attack path

```text
genuine CIC-IDS2017 ATTACK feature row
→ /predict
→ XGBoost ATTACK
→ n8n
→ AbuseIPDB
→ Gemini
→ Analyst Queue
```

The ATTACK replay uses genuine stored 77-feature data but does not originate from a malicious packet capture observed live by the Collector.

Strict live-extractor parity and broader replay validation are reserved for Phase 10.

---

## 25. New / Expanded Backend Endpoints

Phase 9 added or expanded:

```text
WS   /ws/events

POST /collector/heartbeat

GET  /system/status

GET  /dashboard/stats
GET  /dashboard/activity
GET  /dashboard/severity
GET  /dashboard/top-ports
GET  /dashboard/top-sources
GET  /dashboard/attention
```

Existing endpoints remain responsible for inference, persistence, enrichment, analysis, review, and response.

---

## 26. Files Added or Modified

Backend:

```text
backend/app/main.py
backend/app/services/live_events.py
```

Collector:

```text
collector/collector.py
collector/replay_attack.py
```

Dashboard:

```text
dashboard/app/page.tsx
dashboard/app/incidents/[id]/page.tsx
dashboard/app/layout.tsx
```

Automation:

```text
automation/sentinel_detection_automation.json
```

Documentation:

```text
docs/Sentinel_Phase_09_Real_Time_Detection_Live_Monitoring_Analytics.md
docs/assets/phase 9/
README.md
```

---

## 27. Phase 9 Safety Boundaries

Phase 9 preserves the security boundaries introduced earlier:

```text
77-feature ML contract remains isolated from metadata
BENIGN detections do not trigger threat automation
Only ATTACK detections enter n8n
LLM analysis remains advisory
Human review remains mandatory
Response actions remain allowlisted
Actual firewall blocking remains simulated
Secrets remain outside source control
```

The live Collector observes traffic and submits features; it does not receive authority to execute response actions.

---

## 28. Major Concepts Learned

### Packet capture vs flow inference

The model expects flows, not individual packets.

### Stateful aggregation

Real packets must be grouped into bidirectional conversations before ML inference.

### Feature-contract compatibility

A 77-column model is only useful if live feature semantics remain compatible with training.

### WebSockets

Push events remove the need for constant manual browser refreshes.

### Operational monitoring

A detection platform must also expose the health of its own services.

### Attention management

A SOC interface should separate high-volume event history from the smaller set of incidents requiring human action.

### Responsibility boundaries

FastAPI/XGBoost decides whether an event is ATTACK or BENIGN; n8n orchestrates only confirmed model ATTACKs.

### Controlled replay

Known labeled dataset rows provide a safer validation path than attempting to generate harmful real network attacks.

---

## 29. Phase 9 Outcome

Phase 9 is complete.

Sentinel now supports:

- real Windows network packet capture
- a standalone Collector process
- bidirectional flow construction
- CICFlow-style 77-feature extraction
- automatic XGBoost inference
- live BENIGN traffic classification
- PostgreSQL persistence for live flows
- WebSocket dashboard updates
- automatic incident-page updates
- detection activity analytics
- severity distribution
- top targeted ports
- top ATTACK source IPs
- service-health monitoring
- Collector heartbeat monitoring
- automatic health polling
- ATTACK-only n8n routing
- a simplified published n8n workflow
- a sticky Analyst Queue
- genuine CIC-IDS2017 ATTACK replay
- successful DDoS classification
- full ATTACK automation validation through AbuseIPDB and Gemini
- human review handoff

Sentinel has moved from a request-driven security application into a live network monitoring and incident-analysis prototype.

---

## 30. Transition to Phase 10

The next phase is:

```text
Phase 10 - Full Validation & Deployment Readiness
```

Phase 10 will focus on validation and hardening rather than adding another major product layer.

Planned work includes:

- deeper CICFlowMeter parity testing
- replaying multiple BENIGN and ATTACK samples
- checking live extractor consistency against known feature rows
- service-failure scenarios
- n8n timeout / error handling
- AbuseIPDB failure handling
- Gemini failure handling
- PostgreSQL outage behavior
- Collector disconnect/reconnect behavior
- WebSocket reconnect validation
- duplicate/retry behavior
- final security review
- configuration cleanup
- deployment-readiness checks
- final documentation
- final release validation
