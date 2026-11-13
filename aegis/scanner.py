"""Core static & heuristic scanner for untrusted LLM inputs, .docx/.pdf files, and compliance evidence."""

from __future__ import annotations

import base64
import hashlib
import io
import re
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Tuple


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 1.00,
}

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


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


# Trojan Source (CVE-2021-42574) & Bidirectional control codepoints
BIDI_CODEPOINTS = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
}

# Zero-width characters commonly abused to split tokens or hide instructions
ZERO_WIDTH_CODEPOINTS = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (mid-stream)
}

NEAR_WHITE_HEX = {
    "FFFFFF", "FEFEFE", "FDFDFD", "FCFCFC", "FBFBFB", "FAFAFA", "F9F9F9", "F8F8F8",
}


@dataclass(frozen=True)
class _PatternRule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str


PATTERN_RULES: tuple[_PatternRule, ...] = (
    _PatternRule(
        rule_id="AEGIS-INJ-001",
        category="boundary_spoofing",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(<\|im_start\|>\s*system|<\|system\|>|\[INST\]|<<SYS>>|###\s*System\s*Prompt\s*:)",
            re.IGNORECASE,
        ),
        description="Chat-template delimiter or system-role boundary spoofing token detected.",
    ),
    _PatternRule(
        rule_id="AEGIS-INJ-002",
        category="instruction_override",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|system|preceding)\s+"
            r"(instructions?|prompts?|rules?|guardrails?|controls?)\b",
            re.IGNORECASE,
        ),
        description="Explicit instruction-override directive embedded in untrusted text.",
    ),
    _PatternRule(
        rule_id="AEGIS-GRC-003",
        category="verdict_manipulation",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\b(mark|declare|classify|output|set|approve)\s+(this\s+|all\s+|every\s+)?"
            r"(control|requirement|audit|assessment|status|evidence)s?\s+(as\s+)?"
            r"(fully\s+)?(compliant|passed|approved|certified|satisfied)\b",
            re.IGNORECASE,
        ),
        description="Embedded attempt to coerce automated compliance or audit status.",
    ),
    _PatternRule(
        rule_id="AEGIS-EXF-004",
        category="markdown_exfiltration",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*(token|secret|key|context|summary|data|prompt)=",
            re.IGNORECASE,
        ),
        description="Suspicious Markdown image beacon URL with query-parameter exfiltration sink.",
    ),
    _PatternRule(
        rule_id="AEGIS-TOOL-005",
        category="tool_hijack",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(execute_command|run_shell|send_email|curl\s+https?://|wget\s+https?://|invoke_tool)\b",
            re.IGNORECASE,
        ),
        description="Embedded agent tool-invocation or shell execution directive inside document.",
    ),
)

BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
SMUGGLED_KEYWORDS = (
    b"ignore previous",
    b"ignore all previous",
    b"system prompt",
    b"<|im_start|>",
    b"mark all controls",
    b"compliant",
)

PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
PDF_LITERAL_STR_RE = re.compile(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)")
PDF_ACTION_RE = re.compile(rb"/(JavaScript|JS|Launch)\b")
PDF_INVISIBLE_TR_RE = re.compile(r"\b3\s+Tr\b")
PDF_WHITE_FILL_RE = re.compile(r"\b(?:1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+rg|1(?:\.0+)?\s+g)\b")
PDF_MICRO_FONT_RE = re.compile(r"/F\d+\s+(?:0(?:\.\d+)?|1(?:\.0+)?)\s+Tf\b")


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _clean_snippet(text: str, start: int, end: int, max_len: int = 72) -> str:
    raw = text[max(0, start - 12) : min(len(text), end + 12)]
    escaped = raw.replace("\n", "\\n").replace("\r", "\\r")
    if len(escaped) > max_len:
        return escaped[: max_len - 3] + "..."
    return escaped


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _inspect_docx(payload: bytes) -> Tuple[str, List[Finding]]:
    """Unpack OOXML (.docx) in memory, detect hidden/white/1pt text runs, and extract text."""
    findings: List[Finding] = []
    extracted_chunks: List[str] = []
    total_unpacked = 0

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            names = zf.namelist()
            if not any(n.startswith("word/") for n in names):
                return payload.decode("utf-8", errors="replace"), findings

            for name in names:
                if not (name.endswith(".xml") or name.endswith(".rels")):
                    continue
                info = zf.getinfo(name)
                if info.file_size > MAX_ARCHIVE_BYTES or (total_unpacked + info.file_size) > MAX_ARCHIVE_BYTES:
                    break
                total_unpacked += info.file_size
                raw_xml = zf.read(name)
                if b"<!ENTITY" in raw_xml:
                    findings.append(
                        Finding(
                            rule_id="AEGIS-DOC-001",
                            category="hidden_document_text",
                            severity=Severity.CRITICAL,
                            line=1,
                            offset=0,
                            description=f"XML entity declaration inside OOXML archive member '{name}'.",
                            snippet="<!ENTITY ...>",
                        )
                    )
                    continue

                try:
                    root = ET.fromstring(raw_xml)
                except ET.ParseError:
                    continue

                for elem in root.iter():
                    ltag = _local_tag(elem.tag)
                    if ltag == "r":
                        run_texts = [
                            child.text for child in elem.iter()
                            if _local_tag(child.tag) in ("t", "instrText") and child.text
                        ]
                        joined_run = "".join(run_texts).strip()
                        if not joined_run:
                            continue

                        reasons: List[str] = []
                        for prop in elem.iter():
                            ptag = _local_tag(prop.tag)
                            if ptag in ("vanish", "webHidden"):
                                val = next((v for k, v in prop.attrib.items() if _local_tag(k) == "val"), "true")
                                if val.lower() not in ("0", "false", "off"):
                                    reasons.append(f"w:{ptag}")
                            elif ptag == "sz":
                                val = next((v for k, v in prop.attrib.items() if _local_tag(k) == "val"), "")
                                if val.isdigit() and int(val) <= 2:
                                    reasons.append(f"micro-font(w:sz={val})")
                            elif ptag == "color":
                                val = next((v for k, v in prop.attrib.items() if _local_tag(k) == "val"), "")
                                if val.upper() in NEAR_WHITE_HEX:
                                    reasons.append(f"white-text(#{val.upper()})")

                        if reasons:
                            findings.append(
                                Finding(
                                    rule_id="AEGIS-DOC-001",
                                    category="hidden_document_text",
                                    severity=Severity.CRITICAL,
                                    line=1,
                                    offset=0,
                                    description=(
                                        f"Stealth OOXML text run in '{name}' via {', '.join(reasons)}."
                                    ),
                                    snippet=joined_run[:68],
                                )
                            )
                    elif ltag in ("t", "instrText", "description", "subject", "title", "keywords") and elem.text:
                        extracted_chunks.append(elem.text)
    except zipfile.BadZipFile:
        return payload.decode("utf-8", errors="replace"), findings

    return "\n".join(extracted_chunks), findings


def _inspect_pdf(payload: bytes) -> Tuple[str, List[Finding]]:
    """Decompress PDF streams, detect 3 Tr invisible text / white fill / JS actions, and extract strings."""
    findings: List[Finding] = []
    extracted_chunks: List[str] = []

    for match in PDF_ACTION_RE.finditer(payload):
        action = match.group(1).decode("ascii", errors="replace")
        findings.append(
            Finding(
                rule_id="AEGIS-PDF-001",
                category="pdf_stealth_layer",
                severity=Severity.CRITICAL,
                line=1,
                offset=match.start(),
                description=f"Embedded PDF executable action '/{action}' detected.",
                snippet=f"/{action} at byte {match.start()}",
            )
        )

    decoded_streams: List[str] = [payload.decode("latin-1", errors="replace")]
    for idx, smatch in enumerate(PDF_STREAM_RE.finditer(payload)):
        raw_stream = smatch.group(1)
        try:
            decomp = zlib.decompressobj()
            inflated = decomp.decompress(raw_stream, MAX_ARCHIVE_BYTES)
            decoded_streams.append(inflated.decode("latin-1", errors="replace"))
        except Exception:
            continue

    for s_idx, stream_text in enumerate(decoded_streams):
        stealth_reasons: List[str] = []
        if PDF_INVISIBLE_TR_RE.search(stream_text):
            stealth_reasons.append("invisible-render-mode(3 Tr)")
        if PDF_WHITE_FILL_RE.search(stream_text) and ("Tj" in stream_text or "TJ" in stream_text):
            stealth_reasons.append("white-fill(1 1 1 rg)")
        if PDF_MICRO_FONT_RE.search(stream_text):
            stealth_reasons.append("micro-font(<=1pt Tf)")

        literals = [m.group(1) for m in PDF_LITERAL_STR_RE.finditer(stream_text)]
        joined_literals = " ".join(literals).strip()
        if joined_literals:
            extracted_chunks.append(joined_literals)

        if stealth_reasons and s_idx > 0:
            findings.append(
                Finding(
                    rule_id="AEGIS-PDF-001",
                    category="pdf_stealth_layer",
                    severity=Severity.CRITICAL,
                    line=1,
                    offset=0,
                    description=(
                        f"Stealth PDF text operator in stream #{s_idx}: {', '.join(stealth_reasons)}."
                    ),
                    snippet=(joined_literals or stream_text.strip())[:68],
                )
            )

    return "\n".join(extracted_chunks), findings


def _scan_unicode_stego(text: str) -> Iterable[Finding]:
    tag_chars: list[int] = []
    zw_chars: list[int] = []

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp in BIDI_CODEPOINTS:
            yield Finding(
                rule_id="AEGIS-UNI-001",
                category="trojan_bidi",
                severity=Severity.CRITICAL,
                line=_line_number(text, idx),
                offset=idx,
                description=f"Unicode bidirectional override U+{cp:04X} (Trojan Source vector).",
                snippet=f"U+{cp:04X} at offset {idx}",
            )
        elif 0xE0000 <= cp <= 0xE007F:
            tag_chars.append(idx)
        elif cp in ZERO_WIDTH_CODEPOINTS and idx > 0:
            zw_chars.append(idx)

    if tag_chars:
        first = tag_chars[0]
        yield Finding(
            rule_id="AEGIS-UNI-002",
            category="unicode_tag_smuggling",
            severity=Severity.CRITICAL,
            line=_line_number(text, first),
            offset=first,
            description=(
                f"Detected {len(tag_chars)} invisible Unicode Plane-14 Tag character(s) "
                "(ASCII prompt smuggling vector)."
            ),
            snippet=f"{len(tag_chars)} hidden tag codepoints starting at offset {first}",
        )

    if len(zw_chars) >= 3:
        first = zw_chars[0]
        yield Finding(
            rule_id="AEGIS-UNI-003",
            category="zero_width_obfuscation",
            severity=Severity.MEDIUM,
            line=_line_number(text, first),
            offset=first,
            description=(
                f"Detected cluster of {len(zw_chars)} zero-width characters "
                "(token-splitting / watermarking obfuscation)."
            ),
            snippet=f"{len(zw_chars)} zero-width codepoints starting at offset {first}",
        )


def _scan_base64_smuggling(text: str) -> Iterable[Finding]:
    for match in BASE64_CANDIDATE_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        lowered = decoded.lower()
        if any(kw in lowered for kw in SMUGGLED_KEYWORDS):
            preview = decoded.decode("utf-8", errors="replace")[:48]
            yield Finding(
                rule_id="AEGIS-ENC-001",
                category="encoded_payload",
                severity=Severity.HIGH,
                line=_line_number(text, match.start()),
                offset=match.start(),
                description="Base64-encoded prompt-injection payload detected.",
                snippet=f"b64->'{preview}'",
            )


def extract_text_from_bytes(payload: bytes) -> Tuple[str, List[Finding]]:
    """Extract inspectable text and format-specific stealth findings from raw bytes, .docx, or .pdf."""
    if payload.startswith(b"PK\x03\x04"):
        return _inspect_docx(payload)
    if payload.startswith(b"%PDF-"):
        return _inspect_pdf(payload)
    return payload.decode("utf-8", errors="replace"), []


def sanitize_text(text: str) -> str:
    """Strip Trojan Source bidi overrides, Plane-14 tags, zero-width codepoints, and NFKC-normalize."""
    cleaned = "".join(
        ch for ch in text
        if ord(ch) not in BIDI_CODEPOINTS
        and not (0xE0000 <= ord(ch) <= 0xE007F)
        and ord(ch) not in ZERO_WIDTH_CODEPOINTS
    )
    return unicodedata.normalize("NFKC", cleaned)


def sanitize_file(path: str | Path) -> str:
    """Extract text from a text, .docx, or .pdf file and return sanitized, normalized text."""
    raw = Path(path).read_bytes()
    extracted, _ = extract_text_from_bytes(raw)
    return sanitize_text(extracted)


def scan_bytes(payload: bytes, source: str = "<memory>") -> ScanReport:
    digest = hashlib.sha256(payload).hexdigest()
    text, findings = extract_text_from_bytes(payload)

    findings.extend(_scan_unicode_stego(text))

    for rule in PATTERN_RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    line=_line_number(text, match.start()),
                    offset=match.start(),
                    description=rule.description,
                    snippet=_clean_snippet(text, match.start(), match.end()),
                )
            )

    findings.extend(_scan_base64_smuggling(text))
    findings.sort(key=lambda f: (f.offset, f.rule_id))

    raw_score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    risk_score = round(min(1.0, raw_score), 3)

    if any(f.severity == Severity.CRITICAL for f in findings) or risk_score >= 0.70:
        verdict = "QUARANTINE"
    elif findings:
        verdict = "FLAGGED"
    else:
        verdict = "CLEAN"

    return ScanReport(
        source=source,
        sha256=digest,
        byte_length=len(payload),
        risk_score=risk_score,
        verdict=verdict,
        requires_human_review=(verdict != "CLEAN"),
        findings=findings,
    )


def scan_text(text: str, source: str = "<string>") -> ScanReport:
    return scan_bytes(text.encode("utf-8"), source=source)


def scan_file(path: str | Path) -> ScanReport:
    file_path = Path(path)
    return scan_bytes(file_path.read_bytes(), source=str(file_path))
