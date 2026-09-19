import os

import httpx
from dotenv import load_dotenv


load_dotenv()

webhook_url = os.getenv("N8N_WEBHOOK_URL")

payload = {
    "detection_id": 999,
    "prediction": "ATTACK",
    "attack": True,
    "confidence": 0.995,
    "model": "XGBoost"
}

response = httpx.post(
    webhook_url,
    json=payload,
    timeout=10.0
)

print("STATUS CODE:", response.status_code)
print("RESPONSE:")
print(response.json())