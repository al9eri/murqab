# aegis-prompt-guard

[![CI](https://github.com/al9eri/aegis-prompt-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/al9eri/aegis-prompt-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Zero-dependency Python scanner and sanitizer for catching indirect prompt injections, `.docx` / `.pdf` stealth text layers (white-on-white, $\le 1\text{pt}$ micro-fonts, `<w:vanish/>`, PDF `3 Tr` invisible text), Unicode smuggling (Trojan Source, Plane-14 tags), and encoded payloads before LLM or RAG ingestion.

AEGIS unpacks OOXML (`.docx`) and decompresses PDF `/FlateDecode` streams in memory using only the Python standard library (`zipfile`, `xml.etree.ElementTree`, `zlib`, `unicodedata`), gating suspicious files behind SHA-256 provenance digests.

---

## Detection Heuristics & Rules

```text
Raw File (.docx / .pdf / .txt) ──▶ [SHA-256] ──▶ [OOXML / PDF Stealth Unpack] ──▶ [Unicode & Bidi Audit] ──▶ [Injection & Base64 Rules] ──▶ Gate
```

| Rule ID | Category | Severity | Vector Addressed |
| :--- | :--- | :--- | :--- |
| `AEGIS-DOC-001` | `hidden_document_text` | `CRITICAL` | OOXML (`.docx`) stealth runs: `<w:vanish/>`, `<w:webHidden/>`, $\le 1\text{pt}$ micro-fonts (`w:sz <= 2`), or white/near-white font colors (`#FFFFFF`). |
| `AEGIS-PDF-001` | `pdf_stealth_layer` | `CRITICAL` | Decompressed PDF `/FlateDecode` streams using invisible text rendering (`3 Tr`), white fill (`1 1 1 rg`), $\le 1\text{pt}$ fonts, or embedded `/JavaScript` / `/Launch` actions. |
| `AEGIS-UNI-001` | `trojan_bidi` | `CRITICAL` | Unicode bidirectional overrides (`U+202A–U+202E`, `U+2066–U+2069` — CVE-2021-42574 Trojan Source). |
| `AEGIS-UNI-002` | `unicode_tag_smuggling` | `CRITICAL` | Invisible Plane-14 Unicode Tag characters (`U+E0000–U+E007F`) used to smuggle hidden ASCII directives past human reviewers. |
| `AEGIS-UNI-003` | `zero_width_obfuscation` | `MEDIUM` | Clusters of zero-width spaces/joiners (`U+200B–U+200D`, `U+2060`) used to split sensitive tokens. |
| `AEGIS-INJ-001` | `boundary_spoofing` | `CRITICAL` | Chat-template & system-role delimiters (`<\|im_start\|>system`, `[INST]`, `<<SYS>>`, `### System Prompt:`). |
| `AEGIS-INJ-002` | `instruction_override` | `HIGH` | Explicit instruction-override directives (`ignore prior instructions/guardrails/controls`). |
| `AEGIS-GRC-003` | `verdict_manipulation` | `CRITICAL` | Coercive audit-status overrides (`mark all controls as compliant / certified / approved`). |
| `AEGIS-EXF-004` | `markdown_exfiltration` | `HIGH` | Markdown image beacons (`![...](https://...?secret=...)`) designed to exfiltrate context at render time. |
| `AEGIS-TOOL-005` | `tool_hijack` | `HIGH` | Embedded agent tool/shell invocation triggers (`execute_command`, `run_shell`, `curl`). |
| `AEGIS-ENC-001` | `encoded_payload` | `HIGH` | Base64-encoded prompt-injection payloads hidden inside diagnostic or log fields. |

---

## Quick Start

### CLI Usage

```bash
# Scan a single document (.docx, .pdf, .txt) or an entire evidence directory
python -m aegis scan ./evidence_bundle/

# Emit structured JSON with SHA-256 provenance & offsets for CI/CD gating
python -m aegis scan ./vendor_soc2_report.docx --json --strict

# Extract text from .docx/.pdf/.txt, strip invisible Unicode/bidi, and NFKC-normalize
python -m aegis sanitize ./vendor_soc2_report.docx -o ./clean_extract.txt
```

**Exit Codes (`aegis scan`):**
- `0` — `CLEAN` (or `FLAGGED` without `--strict`)
- `1` — `FLAGGED` when running with `--strict`
- `2` — `QUARANTINE` (critical vector or composite risk score $\ge 0.70$; human review mandatory)

### Python Library API

```python
from aegis import sanitize_text, scan_file, scan_text

report = scan_file("vendor_soc2_report.docx")
print(report.verdict)               # "QUARANTINE"
print(report.risk_score)            # 1.0
print(report.requires_human_review) # True
print(report.sha256)                # 64-char SHA-256 provenance digest

clean = sanitize_text("Audit log\u202e with hidden bidi override")
```

---

## Scope & Limitations

- **Structural & Format Pre-Filter:** AEGIS catches deterministic format smuggling (`.docx` vanished/white text, `.pdf` invisible `3 Tr` streams, Unicode bidi/Plane-14 tags, and Base64 payloads). It complements—rather than replaces—semantic LLM guardrails for nuanced natural-language social engineering.
- **Zero External Dependencies:** Built entirely on the Python standard library (`zipfile`, `xml.etree.ElementTree`, `zlib`, `unicodedata`, `re`, `hashlib`) with bounded decompression (`16 MB` cap) against zip/flate bombs.

---

## Running Tests

```bash
pip install pytest
pytest -v
```
