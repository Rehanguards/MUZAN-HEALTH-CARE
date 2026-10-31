from __future__ import annotations

import time
import re
from typing import Any, Dict, List, Optional
from audit import AuditLogger
from redact import Redactor, Result


# Strict Closed Intent Enumeration (Shaky Item 2a: Intent Mapping Layer)
KNOWN_INTENTS = {
    "CLINICAL_QUERY",
    "DOSAGE_REVIEW",
    "PHI_ACCESS",
    "GENERAL_CHAT",
    "RECORD_ACCESS"
}


class HealthcareGuardrailEngine:
    """Enterprise-grade Healthcare & PHI Guardrail Engine for Medical AI Agents.
    
    Leverages Muzan's high-speed redactor, tamper-evident audit logging,
    and strict in-process forward-pass adjudication (<200µs SLA target).
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

        # Fix 1: S-State Persistence Buffer mapped by session_id for multi-turn tracking
        self.session_states: Dict[str, Dict[str, Any]] = {}

        # Refined High-Precision Clinical Safety Patterns with Explicit Authority Lineage
        self.clinical_safety_patterns = {
            "HIGH_RISK_DOSAGE": {
                "pattern": re.compile(
                    r'\b\d+(?:\.\d+)?\s*(?:mg|g|mcg|ml|tablets|capsules)\b\s+(?:daily|every\s+\d+\s+hours|overdose|per day|iv|po|subcutaneously)\b',
                    re.IGNORECASE
                ),
                "rule_id": "RULE_CLINICAL_DOSAGE_LIMIT_01",
                "authority_source": "FDA_CLINICAL_DOSING_GUIDELINES_V4"
            },
            "RESTRICTED_SUBSTANCE": {
                "pattern": re.compile(
                    r'\b(?:fentanyl|morphine|oxycodone|methadone|adderall|xanax|diazepam)\b',
                    re.IGNORECASE
                ),
                "rule_id": "RULE_RESTRICTED_SUBSTANCE_CONTROL_02",
                "authority_source": "DEA_SCHEDULE_CONTROLLED_SUBSTANCES_2026"
            },
            "ICD10_DIAGNOSTIC": {
                "pattern": re.compile(
                    r'\b(?:diag(?:nosis)?|code|icd)[-:\s]+([A-Z][0-9]{2}(?:\.[0-9]{1,2})?)\b',
                    re.IGNORECASE
                ),
                "rule_id": "RULE_ICD10_DIAGNOSTIC_COMPLIANCE_03",
                "authority_source": "CMS_ICD10_CM_2026_SPEC"
            },
        }

    def _normalize_intent(self, intent_str: Optional[str]) -> str:
        """Structural Fix (Shaky Item 2a): Strict intent mapping with conservative fallback."""
        if not intent_str or not isinstance(intent_str, str):
            return "UNKNOWN"
        cleaned = intent_str.strip().upper()
        if cleaned in KNOWN_INTENTS:
            return cleaned
        return "UNKNOWN"

    def inspect_and_guard(self, text: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Inspects medical prompts/outputs with sub-200µs SLA tracking and assurance audit logging."""
        start_ns = time.perf_counter_ns()
        session_id = kwargs.get("session_id") or (args[0] if args else "anonymous")
        raw_intent = kwargs.get("intent", "CLINICAL_QUERY")
        log_audit = kwargs.get("log_audit", True)

        # Fix 1: S-State session initialization and turn incrementing
        if session_id not in self.session_states:
            self.session_states[session_id] = {"turn_count": 0, "history": []}
        session = self.session_states[session_id]
        session["turn_count"] += 1

        if not text:
            elapsed_ns = time.perf_counter_ns() - start_ns
            elapsed_us = round(elapsed_ns / 1000, 2)
            session["history"].append({"turn": session["turn_count"], "decision": "PASS"})
            return {
                "safe": True,
                "decision": "PASS",  # Fix 4: Tri-state output
                "latency_us": elapsed_us,
                "redacted_text": "",
                "violations": [],    
                "within_sla": True,
                "exit_taken": "PASS",
                "session_turns": session["turn_count"]
            }

        violations: List[str] = []
        triggered_rules: List[Dict[str, str]] = []

        # Fix 3: Normalize and Verify Intent (Fail-Closed Check returning UNDETERMINED)
        resolved_intent = self._normalize_intent(raw_intent)
        if resolved_intent == "UNKNOWN":
            elapsed_ns = time.perf_counter_ns() - start_ns
            elapsed_us = round(elapsed_ns / 1000, 2)
            
            if self.audit_logger and log_audit:
                self.audit_logger.log_undetermined_state(
                    reason="GATE_FOLD: Unmapped intent resolved to conservative fallback",
                    raw_payload={"intent": raw_intent, "text_snippet": text[:50]},
                    rule_id="RULE_INTENT_UNKNOWN_FALLBACK",
                    authority_source="MUZAN_FAIL_CLOSED_SPEC_V1",
                    metadata={"session_id": session_id, "latency_us": elapsed_us}
                )

            session["history"].append({"turn": session["turn_count"], "decision": "UNDETERMINED"})
            return {
                "safe": False,
                "decision": "UNDETERMINED",  # Fix 4: Tri-state explicit output
                "latency_us": elapsed_us,
                "redacted_text": text,
                "violations": ["UNMAPPED_INTENT_UNKNOWN"],
                "within_sla": elapsed_ns <= self.sla_budget_ns,
                "exit_taken": "CONSERVATIVE_BLOCK",
                "session_turns": session["turn_count"]
            }

        # 2. Run Muzan core redaction (PHI, MRN, SSN, CARD, etc.)
        redaction_res: Result = self.redactor.redact(text)

        if redaction_res.redactions:
            for r in redaction_res.redactions:
                violations.append(f"PHI_{r.entity}")
                triggered_rules.append({
                    "rule_id": f"RULE_PHI_REDACT_{r.entity}",
                    "authority_source": r.authority_source
                })

        # 3. Check clinical safety and restricted medical constraints against authoritative rules
        for v_name, config in self.clinical_safety_patterns.items():
            if config["pattern"].search(text):
                violations.append(v_name)
                triggered_rules.append({
                    "rule_id": config["rule_id"],
                    "authority_source": config["authority_source"]
                })

        elapsed_ns = time.perf_counter_ns() - start_ns
        elapsed_us = round(elapsed_ns / 1000, 2)
        within_sla = elapsed_ns <= self.sla_budget_ns
        is_flagged = len(violations) > 0

        # Fix 4: Tri-State Outputs definition
        decision = "BLOCK" if is_flagged else "PASS"
        primary_rule = triggered_rules[0]["rule_id"] if triggered_rules else "RULE_CLINICAL_PASSTHROUGH_00"
        primary_authority = triggered_rules[0]["authority_source"] if triggered_rules else "HIPAA_164.312_BASELINE"

        if self.audit_logger and log_audit:
            self.audit_logger.log_decision(
                rule_id=primary_rule,
                authority_source=primary_authority,
                exit_taken=decision,
                verdict="BLOCK" if is_flagged else "ALLOW",
                reason="Clinical safety rules and PHI constraints evaluated successfully" if not is_flagged else f"Violations detected: {list(set(violations))}",
                payload_summary={
                    "violations": list(set(violations)),
                    "session_id": session_id,
                    "intent": resolved_intent,
                    "latency_us": elapsed_us,
                },
                metadata={
                    "sla_budget_ns": self.sla_budget_ns,
                    "within_sla": within_sla
                }
            )

        session["history"].append({"turn": session["turn_count"], "decision": decision})

        return {
            "safe": not is_flagged,
            "decision": decision,  # Fix 4: Tri-State output (PASS / BLOCK)
            "latency_us": elapsed_us,
            "redacted_text": redaction_res.text,
            "violations": list(set(violations)),
            "within_sla": within_sla,
            "exit_taken": decision,
            "session_turns": session["turn_count"]
        }