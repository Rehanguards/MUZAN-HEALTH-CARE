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
        # 1. Direct Identity & PHI Patterns with Explicit Authority Lineage
        self.phi_patterns = [
            {"pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "entity": "SSN", "authority": "HIPAA_164.514_SAFE_HARBOR_A"},
            {"pattern": re.compile(r"\bMRN-\d+\b", re.IGNORECASE), "entity": "MRN", "authority": "HIPAA_164.514_SAFE_HARBOR_C"},
            {"pattern": re.compile(r"\b[2-9]{1}\d{3}\s?\d{4}\s?\d{4}\b"), "entity": "AADHAAR", "authority": "UIDAI_DATA_SECURITY_SPEC"},
            {"pattern": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"), "entity": "PAN", "authority": "IT_ACT_INDIA_COMPLIANCE"},
        ]

        # 2. Identity Explicit Mentions
        self.identity_mention_patterns = [
            {"pattern": re.compile(r"(?i)\b(adhaar|aadhaar|pan\s+card|ssn|mrn)\b"), "rule_id": "RULE_IDENTITY_MENTION_01", "authority": "HIPAA_SAFE_HARBOR"}
        ]

        # 3. Restricted Substances & Lethal Dosages (Strict Case-Insensitive)
        self.restricted_substances = [
            {"pattern": re.compile(r"(?i)\bfentanyl\b"), "rule_id": "RULE_RESTRICTED_FENTANYL", "authority": "DEA_SCHEDULE_II_CONTROL"},
            {"pattern": re.compile(r"(?i)\bmorphine\b"), "rule_id": "RULE_RESTRICTED_MORPHINE", "authority": "DEA_SCHEDULE_II_CONTROL"},
            {"pattern": re.compile(r"(?i)\bpotassium\s+chloride\b"), "rule_id": "RULE_RESTRICTED_KCL", "authority": "FDA_CLINICAL_LETHAL_DOSE_SPEC"},
            {"pattern": re.compile(r"(?i)\bcontrolled\s+substance(s)?\b"), "rule_id": "RULE_CONTROLLED_SUBSTANCES", "authority": "DEA_FEDERAL_REGULATIONS"},
            {"pattern": re.compile(r"(?i)\bnarcotics?\b"), "rule_id": "RULE_NARCOTICS_POLICY", "authority": "HEALTH_POLICY_CONTROL_V4"},
            {"pattern": re.compile(r"(?i)\bopioids?\b"), "rule_id": "RULE_OPIOIDS_POLICY", "authority": "CDC_OPIOID_PRESCRIBING_GUIDELINES"}
        ]

        # 4. Medical Harm, Lethal Dosages & Toxic Lab Safety
        self.clinical_harm_patterns = [
            {"pattern": re.compile(r"(?i)\blethal\s+(dose|dosage|amount)\b"), "rule_id": "RULE_LETHAL_DOSAGE_CHECK", "authority": "FDA_CLINICAL_DOSING_LIMITS"},
            {"pattern": re.compile(r"(?i)\b(fentanyl|morphine|potassium\s+chloride|opioid|narcotic|controlled\s+substance)\b.*\b(overdose|lethal|bypass|fake|unauthorized|without\s+doctor|signature)\b"), "rule_id": "RULE_UNAUTHORIZED_DOSE_BYPASS", "authority": "CLINICAL_SAFETY_MANDATE_2026"},
            {"pattern": re.compile(r"(?i)\bmix\s+chemicals\b.*\b(toxic|poison|harmful|weapon)\b"), "rule_id": "RULE_TOXIC_CHEMICAL_MIX", "authority": "LAB_SAFETY_STANDARD_OSHA"},
            {"pattern": re.compile(r"(?i)\bcreate\s+a?\s+toxic\s+substance\b"), "rule_id": "RULE_TOXIC_SUBSTANCE_CREATION", "authority": "HAZMAT_SAFETY_SPEC"},
            {"pattern": re.compile(r"(?i)\bdouble\s+the\s+maximum\s+safe\s+dosage\b"), "rule_id": "RULE_MAX_DOSAGE_EXCEEDED", "authority": "CLINICAL_PHARMACOPOEIA_STANDARDS"}
        ]

        # 5. Data Destruction, Unmasked Data & System Overrides
        self.adversarial_patterns = [
            {"pattern": re.compile(r"(?i)\bdeveloper\s+mode\b"), "rule_id": "RULE_ADVERSARIAL_DEV_MODE", "authority": "MUZAN_AI_GUARD_SPEC"},
            {"pattern": re.compile(r"(?i)\bsystem\s+override\b"), "rule_id": "RULE_SYSTEM_OVERRIDE_BLOCK", "authority": "MUZAN_AI_GUARD_SPEC"},
            {"pattern": re.compile(r"(?i)\bact\s+as\s+an?\s+(unrestricted|admin)\b"), "rule_id": "RULE_UNRESTRICTED_ROLE_BYPASS", "authority": "AGENT_SANDBOX_SECURITY_V1"},
            {"pattern": re.compile(r"(?i)\bignore\s+previous\s+instructions?\b"), "rule_id": "RULE_PROMPT_INJECTION_IGNORE", "authority": "OWASP_LLM01_DEFENSE"},
            {"pattern": re.compile(r"(?i)\bbypass\s+(all\s+)?(clinical\s+)?guardrails?\b"), "rule_id": "RULE_GUARDRAIL_BYPASS_ATTEMPT", "authority": "MUZAN_FAIL_CLOSED_SPEC"}
        ]

        # 6. Inquiry & Extraction Intent Checks
        self.phi_extraction_patterns = [
            {"pattern": re.compile(r"(?i)\b(what|show|list|retrieve|get|extract|provide|display|pull)\b.*\b(ssn|aadhaar|adhaar|mrn|pan|credit\s+card|dob|date\s+of\s+birth|hiv|psychiatric|oncology|private\s+notes|unmasked|confidential|billing\s+database|patient\s+records?|contact\s+info)\b"), "rule_id": "RULE_PHI_EXTRACTION_INTENT", "authority": "HIPAA_164.312_ACCESS_CONTROL"},
            {"pattern": re.compile(r"(?i)\b(export|dump|reveal)\b.*\b(patient|hipaa|phi|lab\s+reports?|database)\b"), "rule_id": "RULE_BULK_PHI_DUMP_ATTEMPT", "authority": "HIPAA_DATA_EXFIL_DEFENSE"}
        ]

    
    def _normalize_text(self, text: str) -> str:
        if not text:
            return ""
    # Strip all Zero-Width Space/Non-Joiner/BOM/Soft-Hyphen characters
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u2060\u00AD]", "", text)
    
    # Cyrillic-to-Latin Homoglyph Translation Table
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
        return cleaned.translate(trans_table)
    
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

    def inspect_and_guard(self, text: str) -> Dict[str, Any]:
        start_t = time.perf_counter()
        
        # 1. Base64 Unwrapping
        unwrapped_text = self._try_decode_base64(text)
        
        # 2. Unicode / Homoglyph Normalization
        normalized_text = self._normalize_text(unwrapped_text)
        
        violations = []
        triggered_rules = []
        redacted_text = normalized_text

        # A. Check JSON Structural Injections
        # A. Check JSON Structural Injections & Malicious Embedded Commands
        if unwrapped_text.strip().startswith("{") and unwrapped_text.strip().endswith("}"):
            try:
                parsed = json.loads(unwrapped_text)
                if isinstance(parsed, dict):
                    # Check keys or string values for malicious shell/SQL commands
                    payload_str = json.dumps(parsed).lower()
                    dangerous_keywords = ["rm -rf", "drop table", "exec(", "eval(", "system(", "sudo"]
                    
                    if any(kw in payload_str for kw in dangerous_keywords) or "intent" in parsed or "payload" in parsed:
                        violations.append("UNAUTHORIZED_STRUCTURED_JSON_INJECTION")
                        triggered_rules.append({
                            "rule_id": "RULE_MALICIOUS_JSON_PAYLOAD", 
                            "authority": "AGENT_STRUCTURE_VALIDATION_V2"
                        })
            except Exception:
                pass

        # B. Check Restricted Narcotics / Controlled Substances
        for item in self.restricted_substances:
            if re.search(item["pattern"], redacted_text):
                violations.append("RESTRICTED_SUBSTANCE")
                triggered_rules.append({"rule_id": item["rule_id"], "authority": item["authority"]})
                break

        # C. Adversarial / System Override Check
        for item in self.adversarial_patterns:
            if re.search(item["pattern"], redacted_text):
                violations.append("ADVERSARIAL_PROMPT_INJECTION")
                triggered_rules.append({"rule_id": item["rule_id"], "authority": item["authority"]})
                break

        # D. Medical Harm & Chemical Hazards Check
        for item in self.clinical_harm_patterns:
            if re.search(item["pattern"], redacted_text):
                violations.append("CLINICAL_HARM_OR_HAZARD")
                triggered_rules.append({"rule_id": item["rule_id"], "authority": item["authority"]})
                break

        # E. Identity Mentions Check
        for item in self.identity_mention_patterns:
            if re.search(item["pattern"], redacted_text):
                violations.append("IDENTITY_CARD_MENTION")
                triggered_rules.append({"rule_id": item["rule_id"], "authority": item["authority"]})
                break

        # F. PHI Data Extraction Intent Check
        for item in self.phi_extraction_patterns:
            if re.search(item["pattern"], redacted_text):
                violations.append("UNAUTHORIZED_PHI_EXTRACTION_ATTEMPT")
                triggered_rules.append({"rule_id": item["rule_id"], "authority": item["authority"]})
                break

        # G. Direct PHI / Identity Number Leaks
        for item in self.phi_patterns:
            pattern = item["pattern"]
            if re.search(pattern, redacted_text):
                violations.append(f"PHI_{item['entity']}")
                triggered_rules.append({"rule_id": f"RULE_PHI_LEAK_{item['entity']}", "authority": item["authority"]})
                redacted_text = re.sub(pattern, f"[REDACTED_PHI_{item['entity']}]", redacted_text)

        elapsed_us = (time.perf_counter() - start_t) * 1_000_000
        safe = len(violations) == 0

        return {
            "safe": safe,
            "latency_us": elapsed_us,
            "redacted_text": redacted_text,
            "violations": list(set(violations)),
            "triggered_rules": triggered_rules,
            "within_sla": elapsed_us <= 200
        }


class HealthcareCausalGuardrail:
    """Enterprise-grade In-Process Healthcare Causal Guardrail Engine (Spatial Guards / Muzan).
    
    Enforces strict fail-closed adjudication, explicit audit attribution, and sub-200µs SLAs.
    """

    def __init__(self, max_mutations: int = 1, audit_logger: Optional[AuditLogger] = None):
        self.max_mutations = max_mutations
        self.audit_logger = audit_logger or AuditLogger()
        self.healthcare_scanner = HealthcareScanner()
        self.mutation_count = 0

    def inspect_request(self, text: str, session_id: str, action: Optional[ActionUnit] = None) -> Dict[str, Any]:
        # 1. Fail-Closed Check for Malformed Action Units
        if action and (not action.call_id or not action.target or not action.intent):
            details = {"reason": "FAIL_CLOSED_UNDETERMINED_STATE", "action": str(action)}
            self.audit_logger.log_undetermined_state(
                reason="Malformed action unit missing required fields",
                raw_payload={"action": str(action)},
                rule_id="RULE_MALFORMED_ACTION_UNIT",
                authority_source="MUZAN_FAIL_CLOSED_SPEC_V1",
                metadata={"session_id": session_id}
            )
            return {"decision": "BLOCK", "reason": "FAIL_CLOSED_UNDETERMINED_STATE", "exit_taken": "CONSERVATIVE_BLOCK"}

        # 2. Strict Intent Enumeration & Validation
        if action and action.intent.upper() not in ["READ", "WRITE", "REVIEW"]:
            self.audit_logger.log_decision(
                rule_id="RULE_UNKNOWN_OR_MALICIOUS_INTENT",
                authority_source="MUZAN_INTENT_ENFORCEMENT_SPEC",
                exit_taken="CONSERVATIVE_BLOCK",
                verdict="BLOCK",
                reason=f"Unknown or malicious intent provided: {action.intent}",
                payload_summary={"intent": action.intent},
                metadata={"session_id": session_id}
            )
            return {"decision": "BLOCK", "reason": "UNKNOWN_OR_MALICIOUS_INTENT", "exit_taken": "CONSERVATIVE_BLOCK"}

        # 3. Scan Text via HealthcareScanner
        scan_res = self.healthcare_scanner.inspect_and_guard(text)

        # 4. Handle Violations with Assurance Audit Lineage
        if not scan_res["safe"]:
            primary_rule = scan_res["triggered_rules"][0]["rule_id"] if scan_res["triggered_rules"] else "RULE_CLINICAL_SAFETY_VIOLATION"
            primary_authority = scan_res["triggered_rules"][0]["authority"] if scan_res["triggered_rules"] else "CLINICAL_SAFETY_BASELINE"

            self.audit_logger.log_decision(
                rule_id=primary_rule,
                authority_source=primary_authority,
                exit_taken="BLOCK",
                verdict="BLOCK",
                reason=f"Adversarial or clinical violations detected: {scan_res['violations']}",
                payload_summary={
                    "violations": scan_res["violations"],
                    "text_snippet": text[:50],
                    "latency_us": scan_res["latency_us"]
                },
                metadata={"session_id": session_id}
            )
            return {
                "decision": "BLOCK",
                "reason": "ADVERSARIAL_OR_PHI_VIOLATION",
                "exit_taken": "BLOCK",
                "details": scan_res
            }

        # 5. State Mutation Limit Check (Weiwen's Law / Causal Guardrail)
        if action and action.intent.upper() == "WRITE":
            if self.mutation_count >= self.max_mutations:
                self.audit_logger.log_decision(
                    rule_id="RULE_WEIWS_LAW_MUTATION_LIMIT",
                    authority_source="WEIWS_LAW_CAUSAL_CONSTRAINT_V1",
                    exit_taken="BLOCK",
                    verdict="BLOCK",
                    reason="State mutation limit exceeded for session",
                    payload_summary={"mutation_count": self.mutation_count, "max_mutations": self.max_mutations},
                    metadata={"session_id": session_id}
                )
                return {"decision": "BLOCK", "reason": "WEIWS_LAW_MUTATION_LIMIT_EXCEEDED", "exit_taken": "BLOCK"}
            self.mutation_count += 1

        # 6. Pass Decision Lineage Logging
        self.audit_logger.log_decision(
            rule_id="RULE_CLINICAL_PASSTHROUGH_00",
            authority_source="HIPAA_164.312_BASELINE",
            exit_taken="PASS",
            verdict="ALLOW",
            reason="All clinical safety checks, PHI filters, and intent bounds cleared successfully",
            payload_summary={"status": "ALLOWED", "latency_us": scan_res["latency_us"]},
            metadata={"session_id": session_id}
        )
        return {"decision": "PASS", "exit_taken": "PASS", "scan_result": scan_res}