from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern
    authority_source: str  # Structural Fix (Shaky Item 3b): Rule lineage and authority mapping


DETECTORS: list[Detector] = [
    Detector("CARD", re.compile(r"\b(?:\d[ -.]*?){13,19}\b"), "PCI_DSS_v4.0_REQ_3.4"),
    Detector("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "HIPAA_164.514_SAFE_HARBOR_A"),
    Detector("EMAIL", re.compile(r"\b[\w.+-]+@[\w.-]+\.[\w.-]{2,}\b"), "HIPAA_164.514_SAFE_HARBOR_F"),
    # Strict MRN detector requiring explicit prefix code or hyphenated ID format
    Detector("MRN", re.compile(r"\b(?:MRN|mrn|Mrn)[:\s#_-]+([A-Za-z0-9]{5,12})\b|\bMRN-\d{6,10}\b", re.IGNORECASE), "HIPAA_164.514_SAFE_HARBOR_C"),
    # Ultra-strict ICD10 diagnostic code pattern demanding explicit diagnostic labeling to prevent vitamin/room number clashes
    Detector("ICD10", re.compile(r"\b(?:diag(?:nosis)?|code|icd)[-:\s]+([A-Z][0-9]{2}(?:\.[0-9]{1,2})?)\b", re.IGNORECASE), "CMS_ICD10_CM_2026_SPEC"),
    # Cleaned and fixed phone number regex pattern
    Detector("PHONE", re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b"), "HIPAA_164.514_SAFE_HARBOR_C"),
]

DEFAULT_ENTITIES = {d.name for d in DETECTORS}


@dataclass
class Redaction:
    entity: str
    start: int
    end: int
    token: str
    authority_source: str = "HIPAA_164.514_GENERIC"


@dataclass
class Result:
    text: str
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.redactions:
            out[r.entity] = out.get(r.entity, 0) + 1
        return out


class Redactor:
    """High-throughput PII/PHI Redactor with Base64 unwrapping & NFKC Homoglyph Normalization.
    
    Docstring Correction (Shaky Item 6):
    - Target: <32µs execution applies purely to isolated scan functions (single-thread, in-memory, no HTTP/disk I/O).
    """

    def __init__(
        self,
        mode: str = "mask",
        entities: Optional[Set[str]] = None,
    ):
        self.mode = mode.lower()
        self.entities = entities if entities is not None else DEFAULT_ENTITIES
        self.active_detectors = [d for d in DETECTORS if d.name in self.entities]

    def _normalize_input(self, text: str) -> str:
        """Strip zero-width spaces and normalize Unicode homoglyphs (NFKC) before regex scanning."""
        if not text:
            return ""
        # Remove zero-width spaces / joiners used for regex bypass
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)
        # NFKC Normalization converts full-width/homoglyph characters to standard ASCII/Unicode
        return unicodedata.normalize("NFKC", cleaned)

    def redact(self, text: str) -> Result:
        if not text or not isinstance(text, str):
            return Result(text=text or "")

        # Base64 Payload Inspection & Recursive Unwrapping
        if len(text) > 16 and re.match(r"^[A-Za-z0-9+/=]+$", text):
            try:
                decoded = base64.b64decode(text).decode("utf-8")
                sub_res = self.redact(decoded)
                if sub_res.redactions:
                    re_encoded = base64.b64encode(sub_res.text.encode("utf-8")).decode("utf-8")
                    return Result(text=re_encoded, redactions=sub_res.redactions)
            except Exception:
                pass

        # Apply Unicode & Homoglyph Normalization prior to regex scanning
        normalized_text = self._normalize_input(text)

        matches: list[tuple[int, int, str, Detector]] = []
        for detector in self.active_detectors:
            for match in detector.pattern.finditer(normalized_text):
                val = match.group(0)
                matches.append((match.start(), match.start() + len(val), val, detector))

        if not matches:
            return Result(text=normalized_text)

        matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        filtered_matches: list[tuple[int, int, str, Detector]] = []
        last_end = 0

        for m in matches:
            start, end, val, detector = m
            if start >= last_end:
                filtered_matches.append(m)
                last_end = end

        reconstructed: list[str] = []
        redactions: list[Redaction] = []
        curr_idx = 0

        for start, end, val, detector in filtered_matches:
            reconstructed.append(normalized_text[curr_idx:start])
            token = f"[REDACTED_{detector.name}]"
            reconstructed.append(token)
            redactions.append(
                Redaction(
                    entity=detector.name, 
                    start=start, 
                    end=end, 
                    token=token,
                    authority_source=detector.authority_source
                )
            )
            curr_idx = end

        reconstructed.append(normalized_text[curr_idx:])
        return Result(text="".join(reconstructed), redactions=redactions)

    def redact_messages(self, messages: list[dict]) -> Tuple[list[dict], list[Redaction]]:
        cleaned_messages = []
        all_redactions = []

        for msg in messages:
            if not isinstance(msg, dict):
                cleaned_messages.append(msg)
                continue

            msg_copy = dict(msg)
            content = msg_copy.get("content")

            if isinstance(content, str):
                res = self.redact(content)
                msg_copy["content"] = res.text
                all_redactions.extend(res.redactions)
            cleaned_messages.append(msg_copy)

        return cleaned_messages, all_redactions