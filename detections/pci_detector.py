"""PCI-DSS v4.0 / GLBA leak, 99.95% SLO burn, and Config drift detector."""
SLO_ERROR_BUDGET = 0.0005  # 99.95% CDE availability SLO
FAST_BURN_THRESHOLD = SLO_ERROR_BUDGET * 14.4  # 0.0072


def evaluate_detections(event: dict, redactions: list[str]) -> list[dict]:
    alerts: list[dict] = []
    if redactions:
        alerts.append({"rule_id": "PCI-LEAK-001", "runbook": "RB-001", "severity": "CRITICAL"})
    if float(event.get("s3.request.error_rate", 0.0)) >= FAST_BURN_THRESHOLD:
        alerts.append({"rule_id": "PCI-SLO-002", "runbook": "RB-002", "severity": "HIGH"})
    if event.get("config.drift_detected"):
        alerts.append({"rule_id": "PCI-DRIFT-003", "runbook": "RB-003", "severity": "CRITICAL"})
    return alerts
