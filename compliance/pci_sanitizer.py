"""PCI-DSS v4.0 / GLBA in-memory sanitizer with Luhn PAN validation."""
import re

PAN_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
CVV_RE = re.compile(r"\b(?:cvv|cvc|cid)\s*[:=]\s*\d{3,4}\b", re.IGNORECASE)
ABA_RE = re.compile(r"\b(?:routing|aba)\s*[:=]\s*\d{9}\b", re.IGNORECASE)


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def sanitize_text(text: str) -> tuple[str, list[str]]:
    findings: list[str] = []

    def _replace_pan(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if luhn_valid(digits):
            findings.append("PCI-PAN-3.4")
            return f"[REDACTED-PAN-LAST4:{digits[-4:]}]"
        return match.group(0)

    cleaned = PAN_CANDIDATE_RE.sub(_replace_pan, text)
    if CVV_RE.search(cleaned):
        findings.append("PCI-CVV-3.3")
        cleaned = CVV_RE.sub("[PURGED-CVV]", cleaned)
    if ABA_RE.search(cleaned):
        findings.append("GLBA-ABA-ROUTING")
        cleaned = ABA_RE.sub("[REDACTED-ROUTING]", cleaned)
    return cleaned, sorted(set(findings))
