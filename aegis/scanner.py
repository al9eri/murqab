"""Python wrapper over the Rust `aegis._native` scanner and sanitizer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import wraps
import json
from pathlib import Path
from typing import Any, Callable, List

from ._native import (
    filter_mcp_line_native,
    sanitize_bytes_native,
    sanitize_text_native,
    scan_bytes_native,
)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    line: int
    offset: int
    description: str
    snippet: str


@dataclass
class ScanReport:
    source: str
    sha256: str
    byte_length: int
    risk_score: float
    verdict: str
    requires_human_review: bool
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [
            {**asdict(f), "severity": f.severity.value} for f in self.findings
        ]
        return data


def sanitize_text(text: str) -> str:
    """Strip Trojan Source bidi overrides, Plane-14 tags, zero-width codepoints, and NFKC-normalize."""
    return sanitize_text_native(text)


def sanitize_file(path: str | Path) -> str:
    """Extract text from a text, .docx, or .pdf file and return sanitized, normalized text."""
    return sanitize_bytes_native(Path(path).read_bytes())


def scan_bytes(payload: bytes, source: str = "<memory>") -> ScanReport:
    raw = scan_bytes_native(payload, source)
    findings = [
        Finding(
            rule_id=f["rule_id"],
            category=f["category"],
            severity=Severity(f["severity"]),
            line=f["line"],
            offset=f["offset"],
            description=f["description"],
            snippet=f["snippet"],
        )
        for f in raw["findings"]
    ]
    return ScanReport(
        source=raw["source"],
        sha256=raw["sha256"],
        byte_length=raw["byte_length"],
        risk_score=raw["risk_score"],
        verdict=raw["verdict"],
        requires_human_review=raw["requires_human_review"],
        findings=findings,
    )


def scan_text(text: str, source: str = "<string>") -> ScanReport:
    return scan_bytes(text.encode("utf-8"), source=source)


def scan_file(path: str | Path) -> ScanReport:
    file_path = Path(path)
    return scan_bytes(file_path.read_bytes(), source=str(file_path))


def guard_tool(mode: str = "sanitize") -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that scans and blocks/sanitizes tool outputs before an LLM agent consumes them."""
    strict = mode == "block"

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            out = fn(*args, **kwargs)
            payload_str = out if isinstance(out, str) else json.dumps(out, default=str)
            rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": payload_str}})
            filtered, count = filter_mcp_line_native(rpc, strict)
            if count == 0:
                return out
            parsed = json.loads(filtered)
            if "error" in parsed:
                raise PermissionError(parsed["error"]["message"])
            sanitized = parsed["result"]["content"]
            return sanitized if isinstance(out, str) else {"content": sanitized}

        return wrapper

    return decorator
