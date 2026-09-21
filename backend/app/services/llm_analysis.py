import json
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types


load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY was not found in the environment.")

client = genai.Client(api_key=GEMINI_API_KEY)

LLM_PROVIDER = "Google Gemini"
LLM_MODEL = "gemini-3.5-flash-lite"


INCIDENT_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        "severity_reason": {
            "type": "string"
        },
        "summary": {
            "type": "string"
        },
        "likely_activity": {
            "type": "string"
        },
        "reasoning": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "risk_factors": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "recommended_actions": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "analyst_note": {
            "type": "string"
        }
    },
    "required": [
        "severity",
        "severity_reason",
        "summary",
        "likely_activity",
        "reasoning",
        "risk_factors",
        "recommended_actions",
        "analyst_note"
    ],
    "additionalProperties": False
}


def build_incident_context(detection) -> dict:
    return {
        "detection": {
            "id": detection.id,
            "prediction": detection.prediction,
            "attack": detection.attack,
            "confidence": detection.confidence,
            "attack_probability": detection.attack_probability,
            "model": detection.model,
        },
        "network": {
            "source_ip": detection.source_ip,
            "destination_ip": detection.destination_ip,
            "source_port": detection.source_port,
            "destination_port": detection.destination_port,
            "transport_protocol": detection.transport_protocol,
            "observed_at": (
                detection.observed_at.isoformat()
                if detection.observed_at
                else None
            ),
        },
        "threat_intelligence": {
            "provider": detection.threat_provider,
            "data": detection.threat_intelligence,
            "enriched_at": (
                detection.enriched_at.isoformat()
                if detection.enriched_at
                else None
            ),
        },
    }


def build_analysis_prompt(detection) -> str:
    incident_context = build_incident_context(detection)

    return f"""
You are the cybersecurity incident-analysis component inside Sentinel.

Analyze only the evidence provided below.

Rules:
- Do not invent logs, malware, vulnerabilities, users, devices, or events.
- Do not claim that a source IP identifies a physical attacker.
- Clearly distinguish confirmed evidence from inference.
- Use cautious language such as "possible", "likely", or "may" when appropriate.
- Recommendations are advisory only.
- Do not perform or claim to perform remediation.
- Do not assume that an AbuseIPDB report alone proves malicious activity.
- Base the severity on the combined evidence.
- Keep the analysis concise and useful to a security analyst.

Incident evidence:

{json.dumps(incident_context, indent=2)}
""".strip()


def analyze_incident_with_llm(detection) -> dict:
    prompt = build_analysis_prompt(detection)

    response = client.models.generate_content(
        model=LLM_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_json_schema=INCIDENT_ANALYSIS_SCHEMA,
        ),
    )

    return json.loads(response.text)