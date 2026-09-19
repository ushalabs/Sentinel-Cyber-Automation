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
    model: str
):
    payload = {
        "detection_id": detection_id,
        "prediction": prediction,
        "attack": attack,
        "confidence": confidence,
        "model": model
    }

    response = httpx.post(
        N8N_WEBHOOK_URL,
        json=payload,
        timeout=10.0
    )

    response.raise_for_status()

    return response.json()