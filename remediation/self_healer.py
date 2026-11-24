"""Bounded circuit-breaker self-healer for PCI-DSS v4.0 / GLBA telemetry."""
import argparse
import json
from pathlib import Path
import time
from compliance.pci_sanitizer import sanitize_text
from core.system_monitor import collect_telemetry
from detections.pci_detector import evaluate_detections

COOLDOWN_SECONDS = 300


def _in_cooldown(state_dir: Path, rule_id: str, now: float) -> bool:
    stamp = state_dir / f"cooldown_{rule_id}.txt"
    if not stamp.exists():
        return False
    return (now - float(stamp.read_text(encoding="utf-8").strip())) < COOLDOWN_SECONDS


def _build_event(fault: str | None) -> dict:
    if fault == "pan_leak":
        return collect_telemetry("FAULT_INJECTED: Auth log PAN=4532015112830366 cvv=734", "ERROR")
    if fault == "slo_burn":
        return collect_telemetry("FAULT_INJECTED: Elevated CDE S3 PutObject 5xx rate", "ERROR", 0.025)
    if fault == "config_drift":
        ev = collect_telemetry("FAULT_INJECTED: AWS Config drift PublicAccessBlockDisabled", "CRITICAL")
        ev["config.drift_detected"] = True
        return ev
    return collect_telemetry()


def run_pipeline(execute: bool = False, fault: str | None = None, state_dir: Path = Path(".state")) -> dict:
    raw = _build_event(fault)
    cleaned_body, redactions = sanitize_text(raw["event.body"])
    event = {**raw, "event.body": cleaned_body}
    alerts = evaluate_detections(event, redactions)
    actions = []
    now = time.time()
    for alert in alerts:
        rid = alert["rule_id"]
        if not execute:
            actions.append({"rule_id": rid, "runbook": alert["runbook"], "status": "DRY_RUN"})
            continue
        if _in_cooldown(state_dir, rid, now):
            actions.append({"rule_id": rid, "runbook": alert["runbook"], "status": "CIRCUIT_OPEN_SKIPPED"})
            continue
        state_dir.mkdir(parents=True, exist_ok=True)
        (state_dir / f"cooldown_{rid}.txt").write_text(str(now), encoding="utf-8")
        q_file = state_dir / f"quarantine_{rid}_{int(now)}.json"
        q_file.write_text(json.dumps(event, indent=2), encoding="utf-8")
        q_file.chmod(0o600)
        rca = state_dir / f"rca_{rid}_{int(now)}.md"
        rca.write_text(f"# Blameless RCA: {rid}\n- Runbook: {alert['runbook']}\n- Sanitized Body: {event['event.body']}\n", encoding="utf-8")
        actions.append({"rule_id": rid, "runbook": alert["runbook"], "status": "REMEDIATED"})
    return {"event": event, "redactions": redactions, "alerts": alerts, "actions": actions}


def main() -> None:
    parser = argparse.ArgumentParser(description="FinTech CDE Telemetry & Self-Healer")
    parser.add_argument("--execute", action="store_true", help="Execute bounded remediation (default: dry-run)")
    parser.add_argument("--inject-fault", choices=["pan_leak", "slo_burn", "config_drift"], default=None)
    parser.add_argument("--state-dir", type=Path, default=Path(".state"))
    args = parser.parse_args()
    print(json.dumps(run_pipeline(execute=args.execute, fault=args.inject_fault, state_dir=args.state_dir), indent=2))


if __name__ == "__main__":
    main()
