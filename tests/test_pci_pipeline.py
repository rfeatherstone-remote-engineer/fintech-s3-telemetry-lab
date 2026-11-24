"""Zero-dependency unittest suite for FinTech PCI-DSS v4.0 / GLBA pipeline."""
from pathlib import Path
import tempfile
import unittest
from compliance.pci_sanitizer import luhn_valid, sanitize_text
from remediation.self_healer import run_pipeline


class TestPciPipeline(unittest.TestCase):
    def test_luhn_and_redaction(self):
        self.assertTrue(luhn_valid("4532015112830366"))
        self.assertFalse(luhn_valid("4532015112830367"))
        cleaned, tags = sanitize_text("PAN=4532015112830366 cvv=912 routing=021000021")
        self.assertIn("[REDACTED-PAN-LAST4:0366]", cleaned)
        self.assertIn("[PURGED-CVV]", cleaned)
        self.assertIn("[REDACTED-ROUTING]", cleaned)
        self.assertEqual(tags, ["GLBA-ABA-ROUTING", "PCI-CVV-3.3", "PCI-PAN-3.4"])

    def test_chaos_remediation_and_circuit_breaker(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            dry = run_pipeline(execute=False, fault="pan_leak", state_dir=state)
            self.assertEqual(dry["actions"][0]["status"], "DRY_RUN")
            live = run_pipeline(execute=True, fault="pan_leak", state_dir=state)
            self.assertEqual(live["actions"][0]["status"], "REMEDIATED")
            q_files = list(state.glob("quarantine_*.json"))
            self.assertEqual(oct(q_files[0].stat().st_mode & 0o777), "0o600")
            self.assertNotIn("4532015112830366", q_files[0].read_text(encoding="utf-8"))
            trip = run_pipeline(execute=True, fault="pan_leak", state_dir=state)
            self.assertEqual(trip["actions"][0]["status"], "CIRCUIT_OPEN_SKIPPED")
            drift = run_pipeline(execute=False, fault="config_drift", state_dir=state)
            self.assertEqual(drift["alerts"][0]["rule_id"], "PCI-DRIFT-003")


if __name__ == "__main__":
    unittest.main()
