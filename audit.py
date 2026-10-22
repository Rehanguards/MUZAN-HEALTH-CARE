from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    """Muzan Tamper-evident audit logger using HMAC SHA-256 hash chaining.
    
    Hardened with shared class-level locks, thread retry logic, dynamic head synchronization,
    and Shaky-aligned Assurance Metadata (rule_id, authority_source, exit_taken).
    """
    _file_locks = {}

    def __init__(
        self,
        log_dir: str = "./healthcare_audit_logs",
        secret_key: Optional[bytes] = None,
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit.jsonl"
        self.head_file = self.log_dir / ".head"
        
        self.secret_key = secret_key or os.getenv("MUZAN_AUDIT_KEY", "muzan-healthcare-secret-key").encode()
        
        # Shared lock per log file path to prevent cross-instance race conditions
        lock_key = str(self.log_file.resolve())
        if lock_key not in AuditLogger._file_locks:
            AuditLogger._file_locks[lock_key] = threading.Lock()
        self._lock = AuditLogger._file_locks[lock_key]
        
        self.last_hash = self._load_head()

    def _load_head(self) -> str:
        with self._lock:
            return self._load_head_unlocked()

    def _load_head_unlocked(self) -> str:
        if self.head_file.exists():
            val = self.head_file.read_text(encoding="utf-8").strip()
            if val:
                return val
        return "0" * 64

    def _update_head(self, new_hash: str) -> None:
        temp_file = self.log_dir / f".head.tmp.{threading.get_ident()}_{uuid.uuid4().hex[:8]}"
        
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(new_hash)
            f.flush()
            os.fsync(f.fileno())

        max_retries = 5
        for attempt in range(max_retries):
            try:
                temp_file.replace(self.head_file)
                self.last_hash = new_hash
                break
            except (PermissionError, OSError):
                if attempt == max_retries - 1:
                    if temp_file.exists():
                        try:
                            temp_file.unlink()
                        except Exception:
                            pass
                    raise
                time.sleep(0.01 * (2 ** attempt))
        
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass

    def compute_hmac(self, prev_hash: str, payload: str) -> str:
        data = f"{prev_hash}:{payload}".encode("utf-8")
        return hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()

    def log_event(
        self, 
        event_type: str, 
        details: Dict[str, Any], 
        metadata: Optional[Dict[str, Any]] = None,
        sync_to_disk: bool = True
    ) -> str:
        """Logs an event into the tamper-evident HMAC chain with fresh disk synchronization."""
        with self._lock:
            # Dynamically sync with disk head to handle multiple test instances seamlessly
            self.last_hash = self._load_head_unlocked()

            record_body = {
                "timestamp": time.time(),
                "event_type": event_type,
                "details": details,
                "metadata": metadata or {},
            }
            
            serialized_body = json.dumps(record_body, sort_keys=True)
            current_hash = self.compute_hmac(self.last_hash, serialized_body)
            
            full_entry = {
                "prev_hash": self.last_hash,
                "hash": current_hash,
                "body": record_body,
            }

            if sync_to_disk:
                line = json.dumps(full_entry) + "\n"
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())

                self._update_head(current_hash)
            else:
                self.last_hash = current_hash

            return current_hash

    def log_decision(
        self,
        rule_id: str,
        authority_source: str,
        exit_taken: str,
        verdict: str,
        reason: str,
        payload_summary: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Structural Fix (Shaky Item 3c): Logs explicit decision lineage for Assurance.
        
        Records:
        - rule_id: Specific rule identifier triggered
        - authority_source: Standard/Clause/Version backing the rule
        - exit_taken: The exit route executed (PASS, BLOCK, ESCALATE, CONSERVATIVE_BLOCK)
        """
        details = {
            "verdict": verdict,
            "rule_id": rule_id,
            "authority_source": authority_source,
            "exit_taken": exit_taken,
            "reason": reason,
            "payload_summary": payload_summary,
        }
        return self.log_event(event_type="ADJUDICATION_DECISION", details=details, metadata=metadata)

    def log_undetermined_state(
        self, 
        reason: str, 
        raw_payload: Dict[str, Any], 
        rule_id: str = "RULE_UNKNOWN_OR_UNMAPPED",
        authority_source: str = "MUZAN_FAIL_CLOSED_SPEC_V1",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Structural Fix (Shaky Item 2c & 3a): Logs undetermined/unknown states.
        
        Guarantees exit_taken is NEVER 'ALLOW' and records the authority source.
        """
        details = {
            "status": "UNDETERMINED",
            "rule_id": rule_id,
            "authority_source": authority_source,
            "exit_taken": "CONSERVATIVE_BLOCK",
            "reason": reason,
            "raw_payload": raw_payload,
        }
        return self.log_event(event_type="UNDETERMINED_FALLBACK", details=details, metadata=metadata)

    def verify_chain(self) -> bool:
        """Validates the entire audit log file against HMAC tamper checks."""
        with self._lock:
            if not self.log_file.exists():
                return True

            current_expected_prev = "0" * 64
            last_seen_hash = "0" * 64
            
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    
                    if entry["prev_hash"] != current_expected_prev:
                        return False
                    
                    serialized_body = json.dumps(entry["body"], sort_keys=True)
                    recomputed_hash = self.compute_hmac(entry["prev_hash"], serialized_body)
                    
                    if recomputed_hash != entry["hash"]:
                        return False
                    
                    current_expected_prev = entry["hash"]
                    last_seen_hash = entry["hash"]

            self.last_hash = last_seen_hash
            if self.head_file.exists():
                self._update_head(last_seen_hash)

            return True