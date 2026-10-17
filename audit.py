from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    """Muzan Tamper-evident audit logger using HMAC SHA-256 hash chaining."""

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
        self.last_hash = self._load_head()

    def _load_head(self) -> str:
        if self.head_file.exists():
            return self.head_file.read_text().strip()
        return "0" * 64

    def _update_head(self, new_hash: str) -> None:
        temp_file = self.head_file.with_suffix(".tmp")
        with open(temp_file, "w") as f:
            f.write(new_hash)
            f.flush()
            os.fsync(f.fileno())
        temp_file.replace(self.head_file)
        self.last_hash = new_hash

    def compute_hmac(self, prev_hash: str, payload: str) -> str:
        data = f"{prev_hash}:{payload}".encode("utf-8")
        return hmac.new(self.secret_key, data, hashlib.sha256).hexdigest()

    def log_event(self, event_type: str, details: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> str:
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

        line = json.dumps(full_entry) + "\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        self._update_head(current_hash)
        return current_hash

    def verify_chain(self) -> bool:
        """Validates the entire audit log file against HMAC tamper checks."""
        if not self.log_file.exists():
            return True

        current_expected_prev = "0" * 64
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

        return current_expected_prev == self.last_hash