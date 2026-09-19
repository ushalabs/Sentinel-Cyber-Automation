# Sentinel â€” Phase 3 Technical Record
## PostgreSQL Persistence & Detection History

**Project:** Sentinel
**Phase:** 3 â€” Database Persistence & Detection Records
**Status:** âœ… Complete
**Completed:** September 2026

---

## 1. Objective

Phase 3 gave Sentinel persistent memory.

Before this phase, Sentinel could receive a 77-feature network-flow request, run the trained XGBoost model, and return a BENIGN or ATTACK prediction through FastAPI.

However, once the HTTP response was returned, the prediction itself was not stored anywhere.

The goal of Phase 3 was to add permanent database storage so Sentinel could:

- save every detection event
- preserve the original 77-feature payload
- retrieve previous detections
- retrieve a specific detection by ID
- filter detections by attack status
- retain data even after FastAPI restarts

The Phase 3 architecture became:

```text
Network Features
      â†“
POST /predict
      â†“
FastAPI
      â†“
XGBoost
      â†“
Detection Result
      â†“
SQLAlchemy
      â†“
PostgreSQL
      â†“
Persistent Detection History
```

---

## 2. Starting Point

At the start of Phase 3, Sentinel already had:

- a working FastAPI backend
- a production XGBoost model loaded at startup
- a verified 77-feature input contract
- `POST /predict`
- `GET /health`
- `GET /model-info`
- Swagger UI
- successful end-to-end inference testing

The project structure included:

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
    â”œâ”€â”€ venv/
    â””â”€â”€ test_prediction.py
```

The major missing capability was persistent storage.

---

## 3. PostgreSQL Installation

PostgreSQL was installed locally on Windows.

The installed PostgreSQL version was:

```text
PostgreSQL 18.6
```

pgAdmin 4 was installed and used as the graphical administration tool.

The PostgreSQL server was configured locally and verified as running.

---

## 4. Sentinel Database Creation

A dedicated PostgreSQL database was created:

```text
sentinel_db
```

The database was created under the local PostgreSQL server and managed through pgAdmin 4.

This separated Sentinel's application data from the default PostgreSQL maintenance database.

---

## 5. Database Dependencies

Inside Sentinel's Python virtual environment, the following packages were installed:

```text
SQLAlchemy
psycopg[binary]
python-dotenv
```

Their roles:

- **SQLAlchemy** â€” Python ORM / database abstraction
- **psycopg** â€” PostgreSQL driver
- **python-dotenv** â€” loading database configuration from `.env`

---

## 6. Environment Configuration

A `.env` file was created inside:

```text
backend/.env
```

It stores the local database connection settings:

```text
DB_USER
DB_PASSWORD
DB_HOST
DB_PORT
DB_NAME
```

The actual PostgreSQL password is not stored in the project documentation or source repository.

A `.gitignore` file was also created to protect secrets and generated files.

Important ignored entries included:

```gitignore
venv/
.env
__pycache__/
*.pyc
```

This prevents the virtual environment, database credentials, and Python cache files from being committed to Git.

---

## 7. Database Connection Layer

A dedicated database module was created:

```text
backend/app/database.py
```

Its responsibilities include:

- loading `.env`
- constructing the PostgreSQL connection URL
- creating the SQLAlchemy engine
- creating database sessions
- defining the shared SQLAlchemy `Base`
- exposing `get_db()` for FastAPI dependency injection

The connection stack is:

```text
FastAPI
   â†“
SQLAlchemy
   â†“
psycopg
   â†“
PostgreSQL
   â†“
sentinel_db
```

---

## 8. Database Connection Test

The connection was tested directly from the Sentinel virtual environment.

A simple SQL query was executed:

```sql
SELECT version()
```

The result confirmed:

```text
PostgreSQL 18.6
SENTINEL DATABASE CONNECTION SUCCESSFUL
```

This proved that Sentinel's Python backend could successfully communicate with PostgreSQL.

---

## 9. Detection Database Model

A new SQLAlchemy model file was created:

```text
backend/app/models.py
```

The first persistent table was:

```text
detections
```

The `Detection` model contains the following fields:

| Field | Purpose |
|---|---|
| `id` | Primary key |
| `prediction` | BENIGN or ATTACK |
| `attack` | Boolean attack status |
| `confidence` | Confidence in final class |
| `attack_probability` | Raw model attack probability |
| `threshold` | Classification threshold |
| `model` | Model used for inference |
| `features` | Original 77-feature request payload |
| `created_at` | Detection timestamp |

---

## 10. JSONB Feature Storage

The original 77 network features are stored in PostgreSQL as:

```text
JSONB
```

This was intentionally chosen instead of creating 77 separate database columns.

Conceptually, one detection record looks like:

```json
{
  "id": 1,
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.9999658,
  "attack_probability": 0.00003418,
  "threshold": 0.5,
  "model": "XGBoost",
  "features": {
    "Protocol": 0,
    "Flow Duration": 0,
    "...": 0
  },
  "created_at": "2026-09-19T13:32:42..."
}
```

Using JSONB keeps the schema flexible while preserving the exact original feature payload.

---

## 11. Table Creation

The SQLAlchemy metadata was used to create the database table automatically.

After creation, pgAdmin showed:

```text
sentinel_db
â””â”€â”€ Schemas
    â””â”€â”€ public
        â””â”€â”€ Tables
            â””â”€â”€ detections
```

The table contained all 9 expected columns.

This confirmed that the Python ORM model and PostgreSQL schema were synchronized correctly.

---

## 12. Integrating Persistence into `/predict`

The existing prediction endpoint was upgraded.

Before Phase 3:

```text
Input
  â†“
XGBoost
  â†“
JSON Response
```

After Phase 3:

```text
Input
  â†“
XGBoost
  â†“
Detection Object
  â†“
PostgreSQL
  â†“
JSON Response
```

The endpoint now receives a database session using FastAPI dependency injection:

```python
db: Session = Depends(get_db)
```

After XGBoost generates a prediction, Sentinel creates a new `Detection` object and saves it with:

```text
db.add()
db.commit()
db.refresh()
```

If database saving fails:

```text
db.rollback()
```

is used to avoid leaving the session in an invalid transaction state.

---

## 13. Updated Prediction Response

After persistence was added, `/predict` began returning the created database record ID.

The response now includes:

```json
{
  "detection_id": 1,
  "prediction": "BENIGN",
  "attack": false,
  "confidence": 0.999966,
  "attack_probability": 0.000034,
  "threshold": 0.5,
  "model": "XGBoost",
  "created_at": "..."
}
```

The presence of:

```text
detection_id
```

confirms that the prediction was saved as a permanent PostgreSQL record.

---

## 14. First Stored Detection

The existing synthetic all-zero Phase 2 test was sent through `/predict`.

The detection was successfully stored in PostgreSQL.

pgAdmin confirmed the first row:

```text
id = 1
prediction = BENIGN
attack = false
model = XGBoost
```

The full 77-feature payload was stored in the `features` JSONB column.

This was Sentinel's first persistent detection event.

---

## 15. Detection History Endpoint

A new endpoint was added:

```http
GET /detections
```

Its purpose is to retrieve recent detection history.

The endpoint:

- queries the `detections` table
- sorts by newest first
- limits the number of returned results
- returns structured JSON

Default behavior:

```text
limit = 50
```

Example response:

```json
[
  {
    "id": 1,
    "prediction": "BENIGN",
    "attack": false,
    "confidence": 0.9999658,
    "attack_probability": 0.00003418,
    "threshold": 0.5,
    "model": "XGBoost",
    "created_at": "..."
  }
]
```

---

## 16. Detection Filtering

The history endpoint was extended with an optional attack filter.

Examples:

```http
GET /detections?attack=true
```

returns attack detections only.

```http
GET /detections?attack=false
```

returns benign detections only.

This becomes useful later for:

- dashboard views
- incident review
- automation workflows
- n8n queries
- alert systems

---

## 17. Single Detection Endpoint

A second retrieval endpoint was created:

```http
GET /detections/{detection_id}
```

This endpoint returns a full detection record by ID.

Unlike the history endpoint, it includes the original feature payload.

For example:

```http
GET /detections/1
```

returned:

- ID
- prediction
- attack status
- confidence
- attack probability
- threshold
- model
- all 77 stored features
- created timestamp

If the requested ID does not exist, Sentinel returns:

```text
404 Detection not found
```

---

## 18. Persistence Verification

A critical persistence test was performed.

The procedure was:

1. save detection `id = 1`
2. stop the FastAPI server
3. restart Uvicorn
4. call `GET /detections`
5. call `GET /detections/1`

The same detection remained available after restart.

This proved:

> Detection data is stored permanently in PostgreSQL and is not merely held in Python process memory.

---

## 19. API Capabilities After Phase 3

By the end of Phase 3, Sentinel exposed:

```http
GET  /
GET  /health
GET  /model-info
POST /predict
GET  /detections
GET  /detections/{detection_id}
```

The detection history endpoint also supports:

```text
limit
attack=true
attack=false
```

---

## 20. Backend Structure After Phase 3

The backend structure evolved to:

```text
Sentinel/
â”œâ”€â”€ ML Models/
â”‚   â””â”€â”€ XGBoost/
â”‚       â”œâ”€â”€ sentinel_xgboost_binary_v1.json
â”‚       â””â”€â”€ sentinel_feature_columns_v1.joblib
â”‚
â””â”€â”€ backend/
    â”œâ”€â”€ app/
    â”‚   â”œâ”€â”€ main.py
    â”‚   â”œâ”€â”€ database.py
    â”‚   â””â”€â”€ models.py
    â”‚
    â”œâ”€â”€ venv/
    â”œâ”€â”€ .env
    â”œâ”€â”€ .gitignore
    â””â”€â”€ test_prediction.py
```

---

## 21. Concepts Learned

Phase 3 introduced important backend and database concepts.

### PostgreSQL
A production-grade relational database used to persist Sentinel events.

### ORM
SQLAlchemy maps Python classes to database tables.

### Database Engine
The SQLAlchemy engine manages connections to PostgreSQL.

### Database Session
A session represents a unit of interaction with the database.

### Dependency Injection
FastAPI's `Depends(get_db)` provides a database session to API routes.

### Transactions
Changes are committed only after successful database operations.

### Rollback
Failed transactions are safely reverted.

### Environment Variables
Sensitive settings are kept outside source code.

### JSONB
PostgreSQL can efficiently store structured JSON data.

### Persistence
Data remains available after the application process stops and restarts.

### CRUD Foundations
Phase 3 introduced the first parts of CRUD-style application behavior:

```text
Create â†’ POST /predict stores a detection
Read   â†’ GET /detections retrieves detections
```

These concepts are directly relevant to future automation and production applications.

---

## 22. Problems Encountered

### SQLAlchemy installation issue

The first combined pip installation attempt returned:

```text
Could not find a version that satisfies the requirement sqlalchemy
```

The problem was resolved by:

1. upgrading pip
2. installing dependencies individually

After that, all required database packages installed successfully.

### PostgreSQL installation directory issue

The PostgreSQL installer rejected existing non-empty installation directories.

The installation was completed using a fresh installation directory.

---

## 23. Security & Reliability Decisions

Phase 3 included several important safeguards:

- database password stored in `.env`
- `.env` excluded from Git
- database sessions automatically closed
- failed commits rolled back
- prediction history sorted consistently
- missing detection IDs return HTTP 404
- original feature payload preserved for auditability
- detection timestamps stored with timezone information

These choices prepare Sentinel for later production-style automation and incident tracking.

---

## 24. Phase 3 Final Architecture

```text
                 SENTINEL â€” PHASE 3

Network Feature Payload
          â†“
      POST /predict
          â†“
       FastAPI
          â†“
77-Feature Validation
          â†“
      XGBoost
          â†“
BENIGN / ATTACK Result
          â†“
Create Detection Record
          â†“
      SQLAlchemy
          â†“
       psycopg
          â†“
      PostgreSQL
          â†“
     sentinel_db
          â†“
   detections table
          â†“
 â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 â”‚ GET /detections     â”‚
 â”‚ GET /detections/{id}â”‚
 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## 25. Phase 3 Outcome

By the end of Phase 3:

- PostgreSQL 18 was installed and running.
- `sentinel_db` was created.
- FastAPI successfully connected to PostgreSQL.
- SQLAlchemy and psycopg were integrated.
- Database secrets were moved into `.env`.
- `.gitignore` protected local secrets.
- The `detections` table was created.
- Every prediction could be stored permanently.
- The complete original 77-feature payload was preserved.
- Detection history could be retrieved.
- Detections could be filtered by attack status.
- Individual detections could be retrieved by ID.
- Persistence was verified across FastAPI restarts.

Sentinel therefore evolved from a stateless prediction API into a stateful intrusion-detection backend with permanent event history.

---

## 26. Transition to Phase 4

Phase 3 answered:

> **Can Sentinel remember what it detects?**

The answer was yes.

The next challenge is:

> **Can Sentinel automatically react when something important happens?**

Phase 4 introduces the first automation layer using n8n.

The initial target flow is:

```text
Sentinel Detection
       â†“
Webhook
       â†“
n8n
       â†“
Conditional Logic
       â†“
ATTACK?
  â†™        â†˜
YES        NO
 â†“          â†“
Action     Ignore / Log
```

This marks the beginning of Sentinel's AI automation and orchestration layer.

---

## Phase Status

**Phase 3 â€” PostgreSQL Persistence & Detection History: âœ… COMPLETE**
