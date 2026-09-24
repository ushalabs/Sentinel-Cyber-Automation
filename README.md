<p align="center">
  <img src="docs/assets/readme/banner.png" alt="Sentinel Banner" width="100%">
</p>

# Sentinel

Sentinel is a real-time network intrusion detection and incident-response platform that combines machine learning, live traffic collection, threat-intelligence enrichment, LLM-assisted analysis, automation, and human review in one workflow.

## Tech Stack

| Layer | Technology |
|---|---|
| Machine Learning | Python, XGBoost, CIC-IDS2017 |
| Live Collection | Scapy, Npcap |
| Backend | FastAPI, Pydantic, SQLAlchemy, Uvicorn |
| Database | PostgreSQL, psycopg, JSONB |
| Automation | n8n, Webhooks |
| Threat Intelligence | AbuseIPDB |
| LLM Analysis | Google Gemini |
| Dashboard | Next.js, React, TypeScript, Tailwind CSS |
| Live Updates | WebSockets |
| Tooling | Git, GitHub, pgAdmin |

## Development Phases

| Phase | Name |
|---|---|
| 1 | ML Training & Evaluation |
| 2 | FastAPI Model Serving |
| 3 | PostgreSQL Persistence |
| 4 | n8n Automation Foundation |
| 5 | FastAPI → n8n Integration |
| 6 | Threat Intelligence Enrichment |
| 7 | LLM Incident Analysis |
| 8 | Analyst Dashboard + Human Approval & Response |
| 9 | Real-Time Detection + Live Monitoring & Analytics |
| 10 | Full Validation & Deployment Readiness |

## How Sentinel Works

### 1. Live Detection

The Collector captures live TCP/UDP traffic, groups packets into bidirectional flows, builds the required 77-feature CICFlow-style vector, and submits completed flows to FastAPI.

XGBoost classifies each flow as `BENIGN` or `ATTACK`. Every detection is stored in PostgreSQL and streamed to the dashboard.

<p align="center">
  <img src="docs/assets/readme/live_demo.gif" alt="Sentinel Live Detection Demo" width="100%">
</p>

### 2. Attack Automation

BENIGN detections stop after persistence and dashboard delivery.

ATTACK detections continue into the automation pipeline:

```text
ATTACK
  ↓
n8n
  ↓
AbuseIPDB Reputation Check
  ↓
Threat Intelligence Persistence
  ↓
Gemini Incident Analysis
  ↓
Analyst Queue
```

<p align="center">
  <img src="docs/assets/readme/n8n%20flow.png" alt="Sentinel n8n Automation Flow" width="100%">
</p>

### 3. Analyst Dashboard

The dashboard provides live detections, service health, attack confidence, incident review, and an Analyst Queue.

Analysts can inspect incidents, approve or reject response actions, or dismiss an alert from the active queue without deleting its history.

<p align="center">
  <img src="docs/assets/readme/dashboard.png" alt="Sentinel Dashboard" width="100%">
</p>

### 4. Security Analytics

Sentinel summarizes recent activity through severity distribution, targeted ports, source IPs, detection activity, and platform health.

<p align="center">
  <img src="docs/assets/readme/analytics.png" alt="Sentinel Security Analytics" width="100%">
</p>

## Complete Workflow

```text
Live Network Traffic
        ↓
Packet Collector
        ↓
77-Feature Flow Extraction
        ↓
FastAPI
        ↓
XGBoost
        ↓
PostgreSQL
        ↓
 ┌───────────────┴───────────────┐
 ↓                               ↓
BENIGN                         ATTACK
 ↓                               ↓
Dashboard                       n8n
                                 ↓
                          AbuseIPDB Enrichment
                                 ↓
                           Gemini Analysis
                                 ↓
                           Analyst Queue
                                 ↓
                    Approve / Reject / Dismiss
                                 ↓
                     Allowlisted Response Action
                                 ↓
                         Simulation Execution
```

## Using the Repository

### 1. Clone the project

```bash
git clone https://github.com/ushalabs/Sentinel-Cyber-Automation.git
cd Sentinel-Cyber-Automation
```

### 2. Install prerequisites

You will need:

- Python 3.12+
- PostgreSQL
- Node.js and npm
- n8n
- Npcap on Windows for live packet capture
- an AbuseIPDB API key
- a Google Gemini API key

### 3. Prepare the Python backend

Create and activate a virtual environment inside `backend`:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the backend and collector dependencies used by Sentinel:

```powershell
pip install fastapi uvicorn sqlalchemy "psycopg[binary]" python-dotenv pydantic httpx xgboost joblib numpy pandas pyarrow scapy google-genai
```

### 4. Create the PostgreSQL database

Create a local PostgreSQL database named:

```text
sentinel_db
```

Use pgAdmin or PostgreSQL CLI tools to prepare the database schema required by the current `Detection` model.

Then create:

```text
backend/.env
```

with your local configuration:

```env
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_db

N8N_WEBHOOK_URL=http://localhost:5678/webhook/sentinel-detection
GEMINI_API_KEY=your_gemini_key
```

Do not commit `.env`.

### 5. Configure n8n

Start n8n:

```powershell
n8n
```

Open:

```text
http://localhost:5678
```

Import:

```text
automation/sentinel_detection_automation.json
```

Attach your own AbuseIPDB credentials to the reputation-check node and publish the workflow.

The workflow expects FastAPI to be available locally at:

```text
http://127.0.0.1:8000
```

### 6. Start FastAPI

From `backend`:

```powershell
.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

API:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

### 7. Start the dashboard

In a second terminal:

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

### 8. Start the live Collector

Run the Collector from an Administrator PowerShell window so Npcap can capture traffic:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
cd ..\collector
python collector.py
```

The Collector submits completed flows to Sentinel automatically.

If your Windows interface name or local IP differs from the development machine, update the Collector configuration before running it.

## Safety Model

Sentinel keeps response execution controlled:

- BENIGN detections do not enter the attack automation pipeline.
- LLM analysis requires threat-intelligence enrichment.
- Response execution requires explicit analyst approval.
- Response actions are restricted to an allowlist.
- Firewall blocking remains simulated rather than disruptive.
- Duplicate request IDs are handled idempotently.
- Secrets remain outside source control.

## Final Validation

The final controlled end-to-end validation completed with:

```text
15 PASS
0 FAIL
```

This covered the full path from genuine CIC-IDS2017 attack inference through persistence, n8n, AbuseIPDB, Gemini analysis, Analyst Queue review, simulated response execution, and retry protection.

## Dataset

Sentinel uses the CIC-IDS2017 dataset from the Canadian Institute for Cybersecurity, University of New Brunswick.

Dataset and reproduction notes are available under:

```text
Dataset/Dataset_README.md
```

## License

A license has not yet been selected.
