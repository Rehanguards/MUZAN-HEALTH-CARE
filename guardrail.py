from __future__ import annotations

import re
import json
import base64
import time
from typing import Any, Dict, List, Optional
from audit import AuditLogger


class ActionUnit:
    def __init__(self, call_id: str, intent: str, target: str, payload: Dict[str, Any]):
        self.call_id = call_id
        self.intent = intent
        self.target = target
        self.payload = payload


class HealthcareScanner:
    """Enterprise-grade clinical scanner with zero-tolerance case-insensitive matching 
    for PHI, Narcotics/Restricted Substances, Chemical Harm, and Adversarial Prompts.
    """
    def __init__(self):
        # 1. Direct Identity & PHI Patterns
        self.phi_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",          # SSN
            r"\bMRN-\d+\b",                  # MRN
            r"\b[2-9]{1}\d{3}\s?\d{4}\s?\d{4}\b", # Aadhaar Card Pattern
            r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",  # PAN Card Pattern
        ]

        # 2. Identity Explicit Mentions
        self.identity_mention_patterns = [
            r"(?i)\b(adhaar|aadhaar|pan\s+card|ssn|mrn)\b"
        ]

        # 3. Restricted Substances & Lethal Dosages (Strict Case-Insensitive)
        self.restricted_substances = [
            r"(?i)\bfentanyl\b",
            r"(?i)\bmorphine\b",
            r"(?i)\bpotassium\s+chloride\b",
            r"(?i)\bcontrolled\s+substance(s)?\b",
            r"(?i)\bnarcotics?\b",
            r"(?i)\bopioids?\b"
        ]

        # 4. Medical Harm, Lethal Dosages & Toxic Lab Safety
        self.clinical_harm_patterns = [
            r"(?i)\blethal\s+(dose|dosage|amount)\b",
            r"(?i)\b(fentanyl|morphine|potassium\s+chloride|opioid|narcotic|controlled\s+substance)\b.*\b(overdose|lethal|bypass|fake|unauthorized|without\s+doctor|signature)\b",
            r"(?i)\bmix\s+chemicals\b.*\b(toxic|poison|harmful|weapon)\b",
            r"(?i)\bcreate\s+a?\s+toxic\s+substance\b",
            r"(?i)\bexperimental\s+drugs\b.*\b(pediatric|children)\b",
            r"(?i)\bdouble\s+the\s+maximum\s+safe\s+dosage\b",
            r"(?i)\binject\b.*\bwithout\s+approval\b",
            r"(?i)\bbypass\s+prescription\b",
            r"(?i)\bwithout\s+doctor\s+authorization\b",
            r"(?i)\bfake\s+doctor\s+signature\b"
        ]

        # 5. Data Destruction, Unmasked Data & System Overrides
        self.adversarial_patterns = [
            r"(?i)\bdeveloper\s+mode\b",
            r"(?i)\bsystem\s+override\b",
            r"(?i)\bact\s+as\s+an?\s+(unrestricted|admin)\b",
            r"(?i)\bnew\s+system\s+directive\b",
            r"(?i)\bsudo\s+rm\s+-rf\b",
            r"(?i)\badmin_override\b",
            r"(?i)\bpretend\s+there\s+are\s+no\s+rules\b",
            r"(?i)\bdisable\s+security\s+checks?\b",
            r"(?i)\bbypass\s+(all\s+)?(clinical\s+)?guardrails?\b",
            r"(?i)\bemergency\s+override\s+code\b",
            r"(?i)\binclude\s+all\s+hidden\s+phi\b",
            r"(?i)\bignore\s+all\s+safety\s+rules?\b",
            r"(?i)\bignore\s+previous\s+instructions?\b",
            r"(?i)\bevil\s+ai\b",
            r"(?i)\bexposing?\s+(all\s+)?hipaa\b",
            r"(?i)\bdestroy\s+all\s+ehr\b",
            r"(?i)\broot\s+access\b",
            r"(?i)\breveal\s+all\s+(confidential|secrets|keys)\b",
            r"(?i)\bexpose\s+patient\s+private\b"
        ]

        # 6. Inquiry & Extraction Intent Checks
        self.phi_extraction_patterns = [
            r"(?i)\b(what|show|list|retrieve|get|extract|provide|display|pull)\b.*\b(ssn|aadhaar|adhaar|mrn|pan|credit\s+card|dob|date\s+of\s+birth|hiv|psychiatric|oncology|private\s+notes|unmasked|confidential|billing\s+database|patient\s+records?|contact\s+info)\b",
            r"(?i)\b(export|dump|reveal)\b.*\b(patient|hipaa|phi|lab\s+reports?|database)\b",
            r"(?i)\bextract\s+all\s+private\s+health\s+information\b",
            r"(?i)\bcredit\s+card\s+details\b",
            r"(?i)\binsurance\s+policy\s+numbers?\b"
        ]

    def _normalize_text(self, text: str) -> str:
        # Comprehensive Cyrillic-to-Latin homoglyph mapping
        trans_table = str.maketrans({
            'а': 'a', 'А': 'A', 'с': 'c', 'С': 'C',
            'е': 'e', 'Е': 'E', 'і': 'i', 'І': 'I',
            'ј': 'j', 'Ј': 'J', 'р': 'p', 'Р': 'P',
            'ѕ': 's', 'Ѕ': 'S', 'х': 'x', 'Х': 'X',
            'у': 'y', 'У': 'Y', 'о': 'o', 'О': 'O',
            'м': 'm', 'М': 'M', 'т': 't', 'Т': 'T',
            'в': 'v', 'В': 'V', 'н': 'n', 'Н': 'N',
            'к': 'k', 'К': 'K', 'л': 'l', 'Л': 'L',
            'д': 'd', 'Д': 'D', 'п': 'p', 'П': 'P',
            'и': 'i', 'И': 'I', 'г': 'g', 'Г': 'G'
        })
        return text.translate(trans_table)
    
    def _try_decode_base64(self, text: str) -> str:
        cleaned = text.strip()
        if len(cleaned) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', cleaned):
            try:
                decoded_bytes = base64.b64decode(cleaned, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str) > 3:
                    return decoded_str
            except Exception:
                pass
        return text

    def inspect_and_guard(self, text: str, log_audit: bool = True) -> Dict[str, Any]:
        start_t = time.perf_counter()
        
        # 1. Base64 Unwrapping
        unwrapped_text = self._try_decode_base64(text)
        
        # 2. Unicode / Homoglyph Normalization (Catches Cyrillic bypasses)
        normalized_text = self._normalize_text(unwrapped_text)
        
        violations = []
        redacted_text = normalized_text

        # A. Check JSON Structural Injections
        if unwrapped_text.strip().startswith("{") and unwrapped_text.strip().endswith("}"):
            try:
                parsed = json.loads(unwrapped_text)
                if isinstance(parsed, dict) and ("intent" in parsed or "payload" in parsed):
                    violations.append("UNAUTHORIZED_STRUCTURED_JSON_INJECTION")
            except Exception:
                pass

        # B. Check Restricted Narcotics / Controlled Substances
        for pattern in self.restricted_substances:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("RESTRICTED_SUBSTANCE")
                break

        # C. Adversarial / System Override Check
        for pattern in self.adversarial_patterns:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("ADVERSARIAL_PROMPT_INJECTION")
                break

        # D. Medical Harm & Chemical Hazards Check
        for pattern in self.clinical_harm_patterns:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("CLINICAL_HARM_OR_HAZARD")
                break

        # E. Identity Mentions Check
        for pattern in self.identity_mention_patterns:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("IDENTITY_CARD_MENTION")
                break

        # F. PHI Data Extraction Intent Check
        for pattern in self.phi_extraction_patterns:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("UNAUTHORIZED_PHI_EXTRACTION_ATTEMPT")
                break

        # G. Direct PHI / Identity Number Leaks
        for pattern in self.phi_patterns:
            if re.search(pattern, redacted_text, re.IGNORECASE):
                violations.append("PHI_LEAKAGE")
                redacted_text = re.sub(pattern, "[REDACTED_PHI]", redacted_text, flags=re.IGNORECASE)

        elapsed_us = (time.perf_counter() - start_t) * 1_000_000
        safe = len(violations) == 0

        return {
            "safe": safe,
            "latency_us": elapsed_us,
            "redacted_text": redacted_text,
            "violations": violations,
            "within_sla": elapsed_us <= 200
        }


class HealthcareCausalGuardrail:

    def __init__(self, max_mutations: int = 1, audit_logger: Optional[AuditLogger] = None):
        self.max_mutations = max_mutations
        self.audit_logger = audit_logger or AuditLogger()
        self.healthcare_scanner = HealthcareScanner()
        self.mutation_count = 0

    def inspect_request(self, text: str, session_id: str, action: Optional[ActionUnit] = None) -> Dict[str, Any]:
        if action and (not action.call_id or not action.target or not action.intent):
            details = {"reason": "FAIL_CLOSED_UNDETERMINED_STATE", "action": str(action)}
            self.audit_logger.log_undetermined_state("Malformed action unit", details, {"session_id": session_id})
            return {"decision": "BLOCK", "reason": "FAIL_CLOSED_UNDETERMINED_STATE"}

        if action and action.intent.upper() not in ["READ", "WRITE", "REVIEW"]:
            self.audit_logger.log_event("INTENT_BYPASS_ATTEMPT", {"intent": action.intent}, {"session_id": session_id})
            return {"decision": "BLOCK", "reason": "UNKNOWN_OR_MALICIOUS_INTENT"}

        scan_res = self.healthcare_scanner.inspect_and_guard(text)

        if not scan_res["safe"]:
            self.audit_logger.log_event(
                "GUARD_BLOCK", 
                {"violations": scan_res["violations"], "text_snippet": text[:50]}, 
                {"session_id": session_id}
            )
            return {
                "decision": "BLOCK",
                "reason": "ADVERSARIAL_OR_PHI_VIOLATION",
                "details": scan_res
            }

        if action and action.intent.upper() == "WRITE":
            if self.mutation_count >= self.max_mutations:
                self.audit_logger.log_event("STATE_MUTATION_BLOCKED", {"reason": "Max mutations exceeded"}, {"session_id": session_id})
                return {"decision": "BLOCK", "reason": "WEIWS_LAW_MUTATION_LIMIT_EXCEEDED"}
            self.mutation_count += 1

        self.audit_logger.log_event("GUARD_PASS", {"status": "ALLOWED"}, {"session_id": session_id})
        return {"decision": "PASS", "scan_result": scan_res}