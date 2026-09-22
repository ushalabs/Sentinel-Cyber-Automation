from datetime import datetime, timezone


ALLOWED_RESPONSE_ACTIONS = {
    "BLOCK_SOURCE_IP",
    "LOG_ONLY",
}


def execute_response(detection) -> dict:
    action = detection.response_action

    if action not in ALLOWED_RESPONSE_ACTIONS:
        raise ValueError(f"Unsupported response action: {action}")

    if action == "BLOCK_SOURCE_IP":
        return {
            "action": "BLOCK_SOURCE_IP",
            "source_ip": detection.source_ip,
            "executed": True,
            "mode": "SIMULATION",
            "message": (
                f"Simulated blocking of source IP "
                f"{detection.source_ip}"
            ),
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    if action == "LOG_ONLY":
        return {
            "action": "LOG_ONLY",
            "source_ip": detection.source_ip,
            "executed": True,
            "mode": "SIMULATION",
            "message": "Incident recorded with no network action taken.",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }