import os

import httpx
from dotenv import load_dotenv


load_dotenv()

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")


def send_detection_to_n8n(
    detection_id: int,
    prediction: str,
    attack: bool,
    confidence: float,
    model: str,
    source_ip=None,
    destination_ip=None,
    source_port=None,
    destination_port=None,
    transport_protocol=None,
    observed_at=None,
):
    payload = {
        "detection_id": detection_id,
        "prediction": prediction,
        "attack": attack,
        "confidence": confidence,
        "model": model,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "transport_protocol": transport_protocol,
        "observed_at": observed_at.isoformat() if observed_at else None,
    }

    response = httpx.post(
        N8N_WEBHOOK_URL,
        json=payload,
        timeout=60.0
    )

    response.raise_for_status()

    return response.json()