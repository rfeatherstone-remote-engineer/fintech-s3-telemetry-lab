"""Zero-dependency OTel-aligned host & PCI-DSS CDE S3 telemetry collector."""
from datetime import datetime, timezone
import os
import platform


def collect_telemetry(message: str = "CDE vault heartbeat nominal", severity: str = "INFO", error_rate: float = 0.0001) -> dict:
    load1, _, _ = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service.namespace": "fintech-cde",
        "host.arch": platform.machine(),
        "host.cpu.load_1m": round(load1, 4),
        "event.severity": severity,
        "event.body": message,
        "s3.request.error_rate": error_rate,
    }
