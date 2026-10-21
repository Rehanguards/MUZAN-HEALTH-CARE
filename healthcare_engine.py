from __future__ import annotations

import time
import re
from typing import Any, Dict, List, Optional
from audit import AuditLogger
from redact import Redactor, Result


class HealthcareGuardrailEngine:
    """Enterprise-grade Healthcare & PHI Guardrail Engine for Medical AI Agents.
    
    Leverages Muzan's high-speed redactor and tamper-evident audit logging.
    Hardened against clinical false-positives and engineered for strict sub-200µs SLA enforcement.
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        redactor: Optional[Redactor] = None,
        sla_budget_ns: int = 200_000,
    ) -> None:
        self.sla_budget_ns = sla_budget_ns
        self.audit_logger = audit_logger or AuditLogger(log_dir="./healthcare_audit_logs")
        self.redactor = redactor or Redactor(mode="mask")

        # Refined High-Precision Clinical Safety Patterns
        self.clinical_safety_patterns = {
            "HIGH_RISK_DOSAGE": re.compile(
                r'\b\d+(?:\.\d+)?\s*(?:mg|g|mcg|ml|tablets|capsules)\b\s+(?:daily|every\s+\d+\s+hours|overdose|per day|iv|po|subcutaneously)\b',
                re.IGNORECASE
            ),
            "RESTRICTED_SUBSTANCE": re.compile(
                r'\b(?:fentanyl|morphine|oxycodone|methadone|adderall|xanax|diazepam)\b',
                re.IGNORECASE
            ),
            "ICD10_DIAGNOSTIC": re.compile(
                r'\b(?:diag(?:nosis)?|code|icd)[-:\s]+([A-Z][0-9]{2}(?:\.[0-9]{1,2})?)\b',
                re.IGNORECASE
            ),
        }

    def inspect_and_guard(self, text: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Inspects medical prompts/outputs with sub-200µs SLA tracking and audit logging."""
        session_id = kwargs.get("session_id") or (args[0] if args else None)
        log_audit = kwargs.get("log_audit", True)

        if not text:
            return {
                "safe": True,
                "latency_us": 0.0,
                "redacted_text": "",
                "violations": [],
                "within_sla": True
            }

        start_ns = time.perf_counter_ns()
        violations: List[str] = []

        # 1. Run Muzan core redaction (PHI, MRN, SSN, CARD, etc.)
        redaction_res: Result = self.redactor.redact(text)

        if redaction_res.redactions:
            violations.extend([f"PHI_{r.entity}" for r in redaction_res.redactions])

        # 2. Check clinical safety and restricted medical constraints
        for v_name, pattern in self.clinical_safety_patterns.items():
            if pattern.search(text):
                violations.append(v_name)

        elapsed_ns = time.perf_counter_ns() - start_ns
        elapsed_us = round(elapsed_ns / 1000, 2)
        within_sla = elapsed_ns <= self.sla_budget_ns
        is_flagged = len(violations) > 0

        # 3. Log event into tamper-evident HMAC audit chain if violations found and log_audit is True
        if is_flagged and self.audit_logger and log_audit:
            self.audit_logger.log_event(
                event_type="HEALTHCARE_SAFETY_VIOLATION",
                details={
                    "violations": list(set(violations)),
                    "session_id": session_id or "anonymous",
                    "latency_us": elapsed_us,
                },
                metadata={
                    "sla_budget_ns": self.sla_budget_ns,
                    "source_standard": "HIPAA-CLINICAL-V1",
                    "clause_version": "2026.1"
                }
            )

        return {
            "safe": not is_flagged,
            "latency_us": elapsed_us,
            "redacted_text": redaction_res.text,
            "violations": list(set(violations)),
            "within_sla": within_sla,
        }