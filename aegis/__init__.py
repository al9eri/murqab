"""AEGIS — Untrusted Evidence & Indirect Prompt-Injection Scanner (.txt, .docx, .pdf)."""

from .scanner import (
    Finding,
    ScanReport,
    Severity,
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
    "sanitize_file",
    "sanitize_text",
    "scan_bytes",
    "scan_file",
    "scan_text",
]
__version__ = "0.2.0"
