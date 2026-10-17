from __future__ import annotations

import enum
import hashlib
import json
from typing import Any, Dict, Optional, Tuple
from audit import AuditLogger
from healthcare_engine import HealthcareGuardrailEngine


class Decision(str, enum.Enum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    UNDETERMINED = "UNDETERMINED"


class ActionUnit:
    def __init__(
        self,
        call_id: str,
        intent: str,  # e.g., "READ" or "WRITE" (for EHR database updates)
        target: str,
        payload: Optional[Dict[str, Any]] = None,
        parent_id: Optional[str] = None
    ):
        self.call_id = call_id
        self.intent = intent
        self.target = target
        self.payload = payload or {}
        self.parent_id = parent_id


class CausalSession:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.executed_calls: Dict[str, ActionUnit] = {}
        self.cumulative_mutations = 0
        self.state_hash = hashlib.sha256(session_id.encode('utf-8')).hexdigest()

    def record_execution(self, action: ActionUnit) -> "CausalSession":
        self.executed_calls[action.call_id] = action
        if action.intent == "WRITE":
            self.cumulative_mutations += 1

        payload_repr = json.dumps(action.payload, sort_keys=True)
        transition = f"{self.state_hash}:{action.call_id}:{action.intent}:{payload_repr}".encode('utf-8')
        self.state_hash = hashlib.sha256(transition).hexdigest()
        return self


class CausalGuardrailEngine:
    """Weiwen's Law Deterministic Causal Adjudication Engine for Clinical State Control."""
    def __init__(self, max_mutations_per_session: int = 2):
        self.max_mutations = max_mutations_per_session

    def decide_core(self, action: ActionUnit, session: CausalSession) -> Tuple[Decision, CausalSession]:
        if not action.call_id or not action.intent or not action.target:
            return Decision.UNDETERMINED, session

        if action.parent_id and action.parent_id not in session.executed_calls:
            return Decision.UNDETERMINED, session

        # Enforce Weiwen's Law: Block excessive database/EHR write mutations
        if action.intent == "WRITE" and session.cumulative_mutations >= self.max_mutations:
            return Decision.BLOCK, session

        updated_session = session.record_execution(action)
        return Decision.PASS, updated_session


class HealthcareCausalGuardrail:
    """Enterprise Healthcare Guardrail combining PHI Scanning + Weiwen Causal State Engine."""
    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        max_mutations: int = 2,
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.healthcare_scanner = HealthcareGuardrailEngine(audit_logger=self.audit_logger)
        self.causal_engine = CausalGuardrailEngine(max_mutations_per_session=max_mutations)
        self.sessions: Dict[str, CausalSession] = {}

    def get_or_create_session(self, session_id: str) -> CausalSession:
        if session_id not in self.sessions:
            self.sessions[session_id] = CausalSession(session_id)
        return self.sessions[session_id]

    def inspect_request(
        self,
        prompt: str,
        session_id: str,
        action: Optional[ActionUnit] = None
    ) -> Dict[str, Any]:
        """Performs sub-200µs PHI/Clinical inspection AND Causal Mutation verification."""
        
        # 1. Inspect text prompt for PHI, MRN, ICD-10, and High-Risk Dosages
        scan_res = self.healthcare_scanner.inspect_and_guard(prompt, session_id=session_id)
        if not scan_res["safe"]:
            return {
                "decision": "BLOCK",
                "reason": "PHI_OR_CLINICAL_SAFETY_VIOLATION",
                "details": scan_res
            }

        # 2. Evaluate Causal Action Unit if agent is performing a tool call / DB write
        if action:
            session = self.get_or_create_session(session_id)
            decision, updated_session = self.causal_engine.decide_core(action, session)
            self.sessions[session_id] = updated_session

            if decision == Decision.BLOCK:
                self.audit_logger.log_event(
                    event_type="CAUSAL_MUTATION_BREACH_BLOCKED",
                    details={
                        "session_id": session_id,
                        "target": action.target,
                        "cumulative_mutations": session.cumulative_mutations
                    }
                )
                return {
                    "decision": "BLOCK",
                    "reason": "WEIWEIN_CAUSAL_MUTATION_LIMIT_EXCEEDED",
                    "scan_result": scan_res
                }

        return {
            "decision": "PASS",
            "scan_result": scan_res
        }


if __name__ == "__main__":
    print("=== TESTING HEALTHCARE CAUSAL GUARDRAIL ===")
    
    guard = HealthcareCausalGuardrail(max_mutations=1)
    session_id = "patient_session_999"

    # Action 1: First database write (Allowed)
    act1 = ActionUnit(call_id="call_01", intent="WRITE", target="ehr_db_patient_records", payload={"prescription": "Insulin 10 units"})
    res1 = guard.inspect_request("Patient record update for MRN-948201.", session_id=session_id, action=act1)
    print(f"\nRequest 1 Decision: {res1['decision']}")

    # Action 2: Second database write exceeding mutation limit (Blocked by Weiwen's Law)
    act2 = ActionUnit(call_id="call_02", intent="WRITE", target="ehr_db_patient_records", payload={"prescription": "Morphine 50mg"})
    res2 = guard.inspect_request("Another update for MRN-948201.", session_id=session_id, action=act2)
    print(f"Request 2 Decision: {res2['decision']} (Reason: {res2.get('reason')})")

    print(f"\nAudit Chain Verification: {guard.audit_logger.verify_chain()}")