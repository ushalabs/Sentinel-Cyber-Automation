from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    WebSocket,
    WebSocketDisconnect,
    BackgroundTasks,
)
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Detection
from pydantic import BaseModel, Field
from app.services.automation import send_detection_to_n8n
from datetime import datetime, timezone, timedelta
from typing import Literal
from app.services.response_service import execute_response
from fastapi.middleware.cors import CORSMiddleware
from app.services.live_events import manager
from sqlalchemy import func, case
import httpx
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.services.llm_analysis import (
    analyze_incident_with_llm,
    LLM_PROVIDER,
    LLM_MODEL,
)


# ---------------------------------------------------------
# FastAPI
# ---------------------------------------------------------

app = FastAPI(
    title="Sentinel API",
    description="Backend API for Sentinel Network Intrusion Detection System",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "ML Models" / "XGBoost"

MODEL_PATH = MODEL_DIR / "sentinel_xgboost_binary_v1.json"
FEATURES_PATH = MODEL_DIR / "sentinel_feature_columns_v1.joblib"


# ---------------------------------------------------------
# Load Sentinel ML artifacts
# ---------------------------------------------------------

feature_columns = joblib.load(FEATURES_PATH)

model = xgb.Booster()
model.load_model(MODEL_PATH)


if len(feature_columns) != model.num_features():
    raise RuntimeError(
        f"Feature mismatch: saved feature list has "
        f"{len(feature_columns)} features but model expects "
        f"{model.num_features()}."
    )

collector_state = {
    "last_heartbeat": None,
}


# ---------------------------------------------------------
# Request schema
# ---------------------------------------------------------

class NetworkMetadata(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    transport_protocol: str | None = None
    observed_at: datetime | None = None


class PredictionRequest(BaseModel):
    features: dict[str, float]
    metadata: NetworkMetadata | None = None
    trigger_automation: bool = True
    request_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
    )

class ThreatEnrichmentRequest(BaseModel):
    threat_provider: str
    threat_intelligence: dict

class IncidentAnalysis(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_reason: str
    summary: str
    likely_activity: str
    reasoning: list[str]
    risk_factors: list[str]
    recommended_actions: list[str]
    analyst_note: str

class ReviewDecisionRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    action: str | None = None
    note: str | None = None

# ---------------------------------------------------------
# Basic routes
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "project": "Sentinel",
        "status": "online",
        "phase": 10,
        "model": "XGBoost"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
        "model": "XGBoost",
        "expected_features": len(feature_columns)
    }


@app.get("/model-info")
def model_info():
    return {
        "model": "XGBoost",
        "feature_count": len(feature_columns),
        "features": feature_columns
    }


# ---------------------------------------------------------
# ML Prediction
# ---------------------------------------------------------

def _same_prediction_payload(
    detection: Detection,
    request: PredictionRequest,
) -> bool:
    """
    Confirm that an existing request_id belongs to the same network-flow
    payload. Reusing a request_id for different data is rejected.
    """
    metadata = request.metadata

    return (
        detection.features == request.features
        and detection.source_ip == (
            metadata.source_ip if metadata else None
        )
        and detection.destination_ip == (
            metadata.destination_ip if metadata else None
        )
        and detection.source_port == (
            metadata.source_port if metadata else None
        )
        and detection.destination_port == (
            metadata.destination_port if metadata else None
        )
        and detection.transport_protocol == (
            metadata.transport_protocol if metadata else None
        )
        and detection.observed_at == (
            metadata.observed_at if metadata else None
        )
    )


def _idempotent_prediction_response(
    detection: Detection,
    reason: str,
) -> dict:
    """
    Return an already-persisted detection without creating a duplicate row,
    duplicate WebSocket event, or duplicate n8n execution.
    """
    return {
        "detection_id": detection.id,
        "request_id": detection.request_id,
        "prediction": detection.prediction,
        "attack": detection.attack,
        "confidence": round(detection.confidence, 6),
        "attack_probability": round(
            detection.attack_probability,
            6,
        ),
        "threshold": detection.threshold,
        "model": detection.model,
        "created_at": detection.created_at,
        "automation_triggered": False,
        "automation_result": {
            "status": "skipped",
            "reason": reason,
        },
        "idempotent_replay": True,
    }


def _get_existing_request(
    db: Session,
    request: PredictionRequest,
) -> Detection | None:
    if not request.request_id:
        return None

    return (
        db.query(Detection)
        .filter(
            Detection.request_id == request.request_id
        )
        .first()
    )


def _validate_existing_request_payload(
    detection: Detection,
    request: PredictionRequest,
) -> None:
    if not _same_prediction_payload(
        detection,
        request,
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "request_id already exists "
                "with a different payload."
            ),
        )


@app.post("/predict")
def predict(
    request: PredictionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    # Idempotency pre-check.
    existing = _get_existing_request(
        db,
        request,
    )

    if existing is not None:
        _validate_existing_request_payload(
            existing,
            request,
        )

        return _idempotent_prediction_response(
            existing,
            (
                "Duplicate request_id; "
                "existing detection returned."
            ),
        )

    incoming = request.features

    missing_features = [
        feature
        for feature in feature_columns
        if feature not in incoming
    ]

    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Missing required features",
                "missing_features": missing_features,
            },
        )

    ordered_values = [
        incoming[feature]
        for feature in feature_columns
    ]

    values = np.array(
        ordered_values,
        dtype=np.float32,
    ).reshape(1, -1)

    if not np.isfinite(values).all():
        raise HTTPException(
            status_code=400,
            detail="Features contain NaN or infinite values.",
        )

    dmatrix = xgb.DMatrix(
        values,
        feature_names=feature_columns,
    )

    attack_probability = float(
        model.predict(dmatrix)[0]
    )

    predicted_class = (
        1
        if attack_probability >= 0.5
        else 0
    )

    prediction = (
        "ATTACK"
        if predicted_class == 1
        else "BENIGN"
    )

    confidence = (
        attack_probability
        if predicted_class == 1
        else 1 - attack_probability
    )

    metadata = request.metadata

    detection = Detection(
        request_id=request.request_id,
        prediction=prediction,
        attack=predicted_class == 1,
        confidence=float(confidence),
        attack_probability=float(
            attack_probability
        ),
        threshold=0.5,
        model="XGBoost",
        features=incoming,
        source_ip=(
            metadata.source_ip
            if metadata
            else None
        ),
        destination_ip=(
            metadata.destination_ip
            if metadata
            else None
        ),
        source_port=(
            metadata.source_port
            if metadata
            else None
        ),
        destination_port=(
            metadata.destination_port
            if metadata
            else None
        ),
        transport_protocol=(
            metadata.transport_protocol
            if metadata
            else None
        ),
        observed_at=(
            metadata.observed_at
            if metadata
            else None
        ),
    )

    try:
        db.add(detection)
        db.commit()
        db.refresh(detection)

    except IntegrityError:
        # The unique request_id index is the race-condition guard.
        db.rollback()

        existing = _get_existing_request(
            db,
            request,
        )

        if existing is not None:
            _validate_existing_request_payload(
                existing,
                request,
            )

            return _idempotent_prediction_response(
                existing,
                (
                    "Concurrent duplicate request_id; "
                    "existing detection returned."
                ),
            )

        raise HTTPException(
            status_code=500,
            detail=(
                "Prediction succeeded, but saving "
                "detection failed."
            ),
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Prediction succeeded, but saving "
                "detection failed."
            ),
        )

    # Broadcast only genuinely new detections.
    background_tasks.add_task(
        manager.broadcast,
        {
            "event": "DETECTION_CREATED",
            "detection_id": detection.id,
            "request_id": detection.request_id,
            "prediction": detection.prediction,
            "attack": detection.attack,
            "confidence": detection.confidence,
            "created_at": (
                detection.created_at.isoformat()
            ),
        },
    )

    automation_result = None
    automation_triggered = False

    # Only new ATTACK detections may enter n8n.
    if (
        request.trigger_automation
        and predicted_class == 1
    ):
        try:
            automation_result = (
                send_detection_to_n8n(
                    detection_id=detection.id,
                    prediction=prediction,
                    attack=True,
                    confidence=float(confidence),
                    model="XGBoost",
                    source_ip=detection.source_ip,
                    destination_ip=(
                        detection.destination_ip
                    ),
                    source_port=(
                        detection.source_port
                    ),
                    destination_port=(
                        detection.destination_port
                    ),
                    transport_protocol=(
                        detection.transport_protocol
                    ),
                    observed_at=(
                        detection.observed_at
                    ),
                )
            )

            automation_triggered = True

        except Exception as exc:
            automation_result = {
                "error": str(exc),
            }

    else:
        automation_result = {
            "status": "skipped",
            "reason": (
                "BENIGN detection"
                if predicted_class == 0
                else (
                    "automation disabled by "
                    "prediction request"
                )
            ),
        }

    return {
        "detection_id": detection.id,
        "request_id": detection.request_id,
        "prediction": prediction,
        "attack": predicted_class == 1,
        "confidence": round(
            confidence,
            6,
        ),
        "attack_probability": round(
            attack_probability,
            6,
        ),
        "threshold": 0.5,
        "model": "XGBoost",
        "created_at": detection.created_at,
        "automation_triggered": (
            automation_triggered
        ),
        "automation_result": automation_result,
        "idempotent_replay": False,
    }


# ---------------------------------------------------------
# Dashboard Analytics
# ---------------------------------------------------------

@app.get("/dashboard/stats")
def dashboard_stats(
    db: Session = Depends(get_db)
):
    total = db.query(Detection).count()

    attacks = (
        db.query(Detection)
        .filter(Detection.attack.is_(True))
        .count()
    )

    benign = total - attacks

    pending_review = (
        db.query(Detection)
        .filter(Detection.review_status == "PENDING")
        .count()
    )

    critical = (
        db.query(Detection)
        .filter(
            Detection.incident_analysis["severity"].astext
            == "CRITICAL"
        )
        .count()
    )

    attack_rate = (
        round((attacks / total) * 100, 2)
        if total > 0
        else 0.0
    )

    return {
        "total_detections": total,
        "attacks": attacks,
        "benign": benign,
        "attack_rate": attack_rate,
        "pending_review": pending_review,
        "critical_incidents": critical,
    }

@app.get("/dashboard/activity")
def dashboard_activity(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    if hours < 1 or hours > 168:
        raise HTTPException(
            status_code=400,
            detail="hours must be between 1 and 168"
        )

    start_time = (
        datetime.now(timezone.utc)
        - timedelta(hours=hours)
    )

    hour_bucket = func.date_trunc(
        "hour",
        Detection.created_at
    )

    rows = (
        db.query(
            hour_bucket.label("timestamp"),
            func.count(Detection.id).label("total"),
            func.sum(
                case(
                    (Detection.attack.is_(True), 1),
                    else_=0
                )
            ).label("attacks"),
        )
        .filter(Detection.created_at >= start_time)
        .group_by(hour_bucket)
        .order_by(hour_bucket)
        .all()
    )

    return [
        {
            "timestamp": row.timestamp,
            "total": int(row.total),
            "attacks": int(row.attacks or 0),
            "benign": int(row.total) - int(row.attacks or 0),
        }
        for row in rows
    ]

@app.get("/dashboard/severity")
def dashboard_severity(
    db: Session = Depends(get_db)
):
    severity_field = (
        Detection.incident_analysis["severity"].astext
    )

    rows = (
        db.query(
            severity_field.label("severity"),
            func.count(Detection.id).label("count"),
        )
        .filter(
            Detection.attack.is_(True),
            Detection.analysis_status == "COMPLETED",
            Detection.incident_analysis.isnot(None),
        )
        .group_by(severity_field)
        .all()
    )

    counts = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for row in rows:
        if row.severity in counts:
            counts[row.severity] = int(row.count)

    return [
        {
            "severity": severity,
            "count": count,
        }
        for severity, count in counts.items()
    ]

@app.get("/dashboard/top-ports")
def dashboard_top_ports(
    limit: int = 5,
    db: Session = Depends(get_db)
):
    if limit < 1 or limit > 20:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 20"
        )

    rows = (
        db.query(
            Detection.destination_port.label("port"),
            func.count(Detection.id).label("count"),
        )
        .filter(
            Detection.attack.is_(True),
            Detection.destination_port.isnot(None),
        )
        .group_by(Detection.destination_port)
        .order_by(func.count(Detection.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "port": int(row.port),
            "count": int(row.count),
        }
        for row in rows
    ]

@app.get("/dashboard/top-sources")
def dashboard_top_sources(
    limit: int = 5,
    db: Session = Depends(get_db)
):
    if limit < 1 or limit > 20:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 20"
        )

    rows = (
        db.query(
            Detection.source_ip.label("source_ip"),
            func.count(Detection.id).label("count"),
        )
        .filter(
            Detection.attack.is_(True),
            Detection.source_ip.isnot(None),
        )
        .group_by(Detection.source_ip)
        .order_by(func.count(Detection.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "source_ip": row.source_ip,
            "count": int(row.count),
        }
        for row in rows
    ]

@app.get("/system/status")
def system_status(
    db: Session = Depends(get_db)
):
    status = {
        "api": "ONLINE",
        "database": "UNKNOWN",
        "model": "UNKNOWN",
        "n8n": "UNKNOWN",
        "collector": "NOT_STARTED",
    }

    # PostgreSQL
    try:
        db.execute(text("SELECT 1"))
        status["database"] = "ONLINE"
    except Exception:
        status["database"] = "OFFLINE"

    # XGBoost model
    try:
        if (
            model is not None
            and model.num_features() == len(feature_columns)
        ):
            status["model"] = "LOADED"
        else:
            status["model"] = "ERROR"
    except Exception:
        status["model"] = "ERROR"

    # n8n
    try:
        response = httpx.get(
            "http://localhost:5678",
            timeout=2.0,
        )

        status["n8n"] = (
            "ONLINE"
            if response.status_code < 500
            else "OFFLINE"
        )

    except Exception:
        status["n8n"] = "OFFLINE"

    # Collector
    last_heartbeat = collector_state["last_heartbeat"]

    if last_heartbeat is not None:
        age = (
            datetime.now(timezone.utc)
            - last_heartbeat
        ).total_seconds()

        if age <= 15:
            status["collector"] = "RUNNING"
        else:
            status["collector"] = "OFFLINE"

    return status

@app.post("/collector/heartbeat")
def collector_heartbeat():
    collector_state["last_heartbeat"] = datetime.now(timezone.utc)

    return {
        "status": "received",
        "last_heartbeat": collector_state["last_heartbeat"],
    }

@app.get("/dashboard/attention")
def dashboard_attention(
    limit: int = 20,
    db: Session = Depends(get_db),
):
    if limit < 1 or limit > 50:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 50",
        )

    recent_cutoff = (
        datetime.now(timezone.utc)
        - timedelta(minutes=2)
    )

    detections = (
        db.query(Detection)
        .filter(
            Detection.attack.is_(True),
            Detection.source_ip.isnot(None),
            Detection.queue_dismissed.is_(False),
            (
                (Detection.review_status == "PENDING")
                | (Detection.analysis_status == "PENDING")
                | (Detection.analysis_status == "FAILED")
                | (
                    (Detection.analysis_status == "NOT_STARTED")
                    & (Detection.created_at >= recent_cutoff)
                )
            ),
        )
        .order_by(Detection.created_at.desc())
        .limit(limit)
        .all()
    )

    result = []

    for detection in detections:
        analysis = detection.incident_analysis or {}

        if detection.analysis_status == "FAILED":
            attention_state = "ANALYSIS_FAILED"

        elif detection.review_status == "PENDING":
            attention_state = "PENDING_REVIEW"

        else:
            attention_state = "ANALYZING"

        result.append(
            {
                "id": detection.id,
                "prediction": detection.prediction,
                "confidence": detection.confidence,
                "attack_probability": detection.attack_probability,

                "source_ip": detection.source_ip,
                "destination_ip": detection.destination_ip,
                "source_port": detection.source_port,
                "destination_port": detection.destination_port,
                "transport_protocol": detection.transport_protocol,

                "severity": analysis.get("severity"),
                "analysis_status": detection.analysis_status,
                "review_status": detection.review_status,
                "attention_state": attention_state,
                "queue_dismissed": detection.queue_dismissed,
                "queue_dismissed_at": detection.queue_dismissed_at,

                "created_at": detection.created_at,
            }
        )

    return result

@app.post("/detections/{detection_id}/dismiss-from-queue")
def dismiss_detection_from_queue(
    detection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    detection = (
        db.query(Detection)
        .filter(Detection.id == detection_id)
        .first()
    )

    if detection is None:
        raise HTTPException(
            status_code=404,
            detail="Detection not found",
        )

    if not detection.attack:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only ATTACK detections can be "
                "dismissed from the Analyst Queue."
            ),
        )

    # Safe to click more than once.
    if detection.queue_dismissed:
        return {
            "detection_id": detection.id,
            "queue_dismissed": True,
            "queue_dismissed_at": detection.queue_dismissed_at,
            "message": (
                "Detection was already dismissed "
                "from the Analyst Queue."
            ),
        }

    detection.queue_dismissed = True
    detection.queue_dismissed_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(detection)

        background_tasks.add_task(
            manager.broadcast,
            {
                "event": "QUEUE_DISMISSED",
                "detection_id": detection.id,
                "queue_dismissed": True,
            },
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to dismiss detection "
                "from Analyst Queue."
            ),
        )

    return {
        "detection_id": detection.id,
        "queue_dismissed": detection.queue_dismissed,
        "queue_dismissed_at": detection.queue_dismissed_at,
        "message": (
            "Removed from Analyst Queue. "
            "Detection history was preserved."
        ),
    }


# ---------------------------------------------------------
# Detection History
# ---------------------------------------------------------

@app.get("/detections")
def get_detections(
    limit: int = 50,
    attack: bool | None = None,
    db: Session = Depends(get_db)
):
    query = db.query(Detection)

    if attack is not None:
        query = query.filter(Detection.attack == attack)

    detections = (
        query
        .order_by(Detection.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": detection.id,
            "request_id": detection.request_id,
            "prediction": detection.prediction,
            "attack": detection.attack,
            "confidence": detection.confidence,
            "attack_probability": detection.attack_probability,
            "threshold": detection.threshold,
            "model": detection.model,
            "created_at": detection.created_at
        }
        for detection in detections
    ]


@app.get("/detections/{detection_id}")
def get_detection(
    detection_id: int,
    db: Session = Depends(get_db)
):
    detection = (
        db.query(Detection)
        .filter(Detection.id == detection_id)
        .first()
    )

    if detection is None:
        raise HTTPException(
            status_code=404,
            detail="Detection not found"
        )

    return {
    "id": detection.id,
    "request_id": detection.request_id,

    # ML detection
    "prediction": detection.prediction,
    "attack": detection.attack,
    "confidence": detection.confidence,
    "attack_probability": detection.attack_probability,
    "threshold": detection.threshold,
    "model": detection.model,
    "created_at": detection.created_at,

    # Network metadata
    "source_ip": detection.source_ip,
    "destination_ip": detection.destination_ip,
    "source_port": detection.source_port,
    "destination_port": detection.destination_port,
    "transport_protocol": detection.transport_protocol,
    "observed_at": detection.observed_at,

    # Threat intelligence
    "threat_provider": detection.threat_provider,
    "threat_intelligence": detection.threat_intelligence,
    "enriched_at": detection.enriched_at,

    # LLM analysis
    "llm_provider": detection.llm_provider,
    "llm_model": detection.llm_model,
    "incident_analysis": detection.incident_analysis,
    "analysis_status": detection.analysis_status,
    "analysis_error": detection.analysis_error,
    "analyzed_at": detection.analyzed_at,

    # Human review
    "review_status": detection.review_status,
    "review_note": detection.review_note,
    "reviewed_at": detection.reviewed_at,

    # Analyst Queue
    "queue_dismissed": detection.queue_dismissed,
    "queue_dismissed_at": detection.queue_dismissed_at,

    # Response
    "response_action": detection.response_action,
    "response_status": detection.response_status,
    "response_result": detection.response_result,
    "responded_at": detection.responded_at,
}

@app.post("/detections/{detection_id}/enrichment")
def save_threat_enrichment(
    detection_id: int,
    payload: ThreatEnrichmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    detection = (
        db.query(Detection)
        .filter(Detection.id == detection_id)
        .first()
    )

    if detection is None:
        raise HTTPException(
            status_code=404,
            detail="Detection not found"
        )

    if not detection.attack:
        raise HTTPException(
        status_code=400,
        detail="Threat intelligence enrichment is only allowed for ATTACK detections"
    )

    detection.threat_provider = payload.threat_provider
    detection.threat_intelligence = payload.threat_intelligence
    detection.enriched_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(detection)
        background_tasks.add_task(
    manager.broadcast,
    {
        "event": "THREAT_INTELLIGENCE_UPDATED",
        "detection_id": detection.id,
    },
)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to save threat intelligence"
        )

    return {
        "detection_id": detection.id,
        "threat_provider": detection.threat_provider,
        "threat_intelligence": detection.threat_intelligence,
        "enriched_at": detection.enriched_at,
        "message": "Threat intelligence saved successfully",
    }

@app.post("/detections/{detection_id}/analysis")
def analyze_detection(
    detection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    detection = db.query(Detection).filter(Detection.id == detection_id).first()

    if not detection:
        raise HTTPException(
            status_code=404,
            detail="Detection not found"
        )

    if not detection.attack:
        raise HTTPException(
            status_code=400,
            detail="LLM analysis is only allowed for ATTACK detections"
        )

    if not detection.threat_intelligence:
        raise HTTPException(
            status_code=400,
            detail="Threat intelligence must exist before LLM analysis"
        )

    try:
        detection.analysis_status = "PENDING"
        detection.analysis_error = None
        db.commit()

        raw_analysis = analyze_incident_with_llm(detection)

        validated_analysis = IncidentAnalysis(**raw_analysis)

        detection.llm_provider = LLM_PROVIDER
        detection.llm_model = LLM_MODEL
        detection.incident_analysis = validated_analysis.model_dump()
        detection.analysis_status = "COMPLETED"
        detection.analysis_error = None
        detection.analyzed_at = datetime.now(timezone.utc)
        detection.review_status = "PENDING"

        db.commit()
        db.refresh(detection)
        background_tasks.add_task(
        manager.broadcast,
        {
        "event": "ANALYSIS_COMPLETED",
        "detection_id": detection.id,
        "severity": detection.incident_analysis.get("severity")
        if detection.incident_analysis
        else None,
    },
)

        return {
            "detection_id": detection.id,
            "analysis_status": detection.analysis_status,
            "llm_provider": detection.llm_provider,
            "llm_model": detection.llm_model,
            "incident_analysis": detection.incident_analysis,
            "analyzed_at": detection.analyzed_at,
        }

    except Exception as exc:
        db.rollback()

        detection.analysis_status = "FAILED"
        detection.analysis_error = str(exc)

        db.commit()

        raise HTTPException(
            status_code=500,
            detail="LLM incident analysis failed"
        )

@app.post("/detections/{detection_id}/review")
def review_detection(
    detection_id: int,
    payload: ReviewDecisionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    detection = db.query(Detection).filter(
        Detection.id == detection_id
    ).first()

    if not detection:
        raise HTTPException(
            status_code=404,
            detail="Detection not found"
        )

    if not detection.attack:
        raise HTTPException(
            status_code=400,
            detail="Human review is only allowed for ATTACK detections"
        )

    if detection.analysis_status != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail="LLM analysis must be completed before human review"
        )

    if detection.review_status in {"APPROVED", "REJECTED"}:
        raise HTTPException(
            status_code=409,
            detail="Detection has already been reviewed"
        )

    if payload.decision == "APPROVE":
        if not payload.action:
            raise HTTPException(
                status_code=400,
                detail="An action is required when approving a detection"
            )

        detection.review_status = "APPROVED"
        detection.response_action = payload.action
        detection.response_status = "PENDING"

    elif payload.decision == "REJECT":
        detection.review_status = "REJECTED"
        detection.response_action = None
        detection.response_status = "NOT_STARTED"

    detection.review_note = payload.note
    detection.reviewed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(detection)
    background_tasks.add_task(
    manager.broadcast,
    {
        "event": "REVIEW_UPDATED",
        "detection_id": detection.id,
        "review_status": detection.review_status,
        "response_action": detection.response_action,
        "response_status": detection.response_status,
    },
)

    return {
        "detection_id": detection.id,
        "review_status": detection.review_status,
        "review_note": detection.review_note,
        "reviewed_at": detection.reviewed_at,
        "response_action": detection.response_action,
        "response_status": detection.response_status,
    }

@app.post("/detections/{detection_id}/respond")
def respond_to_detection(
    detection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    detection = db.query(Detection).filter(
        Detection.id == detection_id
    ).first()

    if not detection:
        raise HTTPException(
            status_code=404,
            detail="Detection not found"
        )

    if not detection.attack:
        raise HTTPException(
            status_code=400,
            detail="Response actions are only allowed for ATTACK detections"
        )

    if detection.review_status != "APPROVED":
        raise HTTPException(
            status_code=403,
            detail="Human approval is required before executing a response"
        )

    if detection.response_status == "EXECUTED":
        raise HTTPException(
            status_code=409,
            detail="Response has already been executed"
        )

    if not detection.response_action:
        raise HTTPException(
            status_code=400,
            detail="No response action has been selected"
        )

    try:
        result = execute_response(detection)

        detection.response_status = "EXECUTED"
        detection.response_result = result
        detection.responded_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(detection)
        background_tasks.add_task(
        manager.broadcast,
        {
        "event": "RESPONSE_UPDATED",
        "detection_id": detection.id,
        "response_action": detection.response_action,
        "response_status": detection.response_status,
    },
)

        return {
            "detection_id": detection.id,
            "response_action": detection.response_action,
            "response_status": detection.response_status,
            "response_result": detection.response_result,
            "responded_at": detection.responded_at,
        }

    except Exception as exc:
        db.rollback()

        detection.response_status = "FAILED"
        detection.response_result = {
            "error": str(exc)
        }
        detection.responded_at = datetime.now(timezone.utc)

        db.commit()

        raise HTTPException(
            status_code=500,
            detail="Response execution failed"
        )
