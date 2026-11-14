"""MURQAB — Untrusted Evidence & Indirect Prompt-Injection Scanner (.txt, .docx, .pdf)."""

from .scanner import (
    Finding,
    ScanReport,
    Severity,
    guard_tool,
    sanitize_file,
    sanitize_text,
    scan_bytes,
    scan_file,
    scan_text,
)

__all__ = [
    "Finding",
    "ScanReport",
    "Severity",
    "guard_tool",
    "sanitize_file",
    "sanitize_text",
    "scan_bytes",
    "scan_file",
    "scan_text",
]
__version__ = "0.4.0"
