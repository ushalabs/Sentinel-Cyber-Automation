from pathlib import Path

import joblib
import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Detection
from pydantic import BaseModel
from app.services.automation import send_detection_to_n8n
from datetime import datetime, timezone
from typing import Literal

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

# ---------------------------------------------------------
# Basic routes
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "project": "Sentinel",
        "status": "online",
        "phase": 2,
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

@app.post("/predict")
def predict(
    request: PredictionRequest,
    db: Session = Depends(get_db)
):

    incoming = request.features

    missing_features = [
        feature for feature in feature_columns
        if feature not in incoming
    ]

    if missing_features:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Missing required features",
                "missing_features": missing_features
            }
        )

    ordered_values = [
        incoming[feature]
        for feature in feature_columns
    ]

    values = np.array(
        ordered_values,
        dtype=np.float32
    ).reshape(1, -1)

    if not np.isfinite(values).all():
        raise HTTPException(
            status_code=400,
            detail="Features contain NaN or infinite values."
        )

    dmatrix = xgb.DMatrix(
        values,
        feature_names=feature_columns
    )

    attack_probability = float(model.predict(dmatrix)[0])

    predicted_class = 1 if attack_probability >= 0.5 else 0

    prediction = "ATTACK" if predicted_class == 1 else "BENIGN"

    confidence = (
        attack_probability
        if predicted_class == 1
        else 1 - attack_probability
    )

    detection = Detection(
        prediction=prediction,
        attack=predicted_class == 1,
        confidence=float(confidence),
        attack_probability=float(attack_probability),
        threshold=0.5,
        model="XGBoost",
        features=incoming,

        source_ip=request.metadata.source_ip if request.metadata else None,
        destination_ip=request.metadata.destination_ip if request.metadata else None,
        source_port=request.metadata.source_port if request.metadata else None,
        destination_port=request.metadata.destination_port if request.metadata else None,
        transport_protocol=request.metadata.transport_protocol if request.metadata else None,
        observed_at=request.metadata.observed_at if request.metadata else None,
    )

    try:
        db.add(detection)
        db.commit()
        db.refresh(detection)

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Prediction succeeded, but saving detection failed."
        )

    automation_result = None
    automation_triggered = False

    try:
        automation_result = send_detection_to_n8n(
            detection_id=detection.id,
            prediction=prediction,
            attack=predicted_class == 1,
            confidence=float(confidence),
            model="XGBoost",
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            source_port=detection.source_port,
            destination_port=detection.destination_port,
            transport_protocol=detection.transport_protocol,
            observed_at=detection.observed_at,
        )

        automation_triggered = True

    except Exception as exc:
        automation_result = {
            "error": str(exc)
        }

    return {
        "detection_id": detection.id,
        "prediction": prediction,
        "attack": predicted_class == 1,
        "confidence": round(confidence, 6),
        "attack_probability": round(attack_probability, 6),
        "threshold": 0.5,
        "model": "XGBoost",
        "created_at": detection.created_at,
        "automation_triggered": automation_triggered,
        "automation_result": automation_result
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
        "prediction": detection.prediction,
        "attack": detection.attack,
        "confidence": detection.confidence,
        "attack_probability": detection.attack_probability,
        "threshold": detection.threshold,
        "model": detection.model,
        "features": detection.features,
        "created_at": detection.created_at
    }

@app.post("/detections/{detection_id}/enrichment")
def save_threat_enrichment(
    detection_id: int,
    payload: ThreatEnrichmentRequest,
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

        db.commit()
        db.refresh(detection)

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