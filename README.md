# aegis-prompt-guard

[![CI](https://github.com/al9eri/aegis-prompt-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/al9eri/aegis-prompt-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Rust-accelerated scanner and sanitizer for catching indirect prompt injections, `.docx` / `.pdf` stealth text layers (white-on-white, $\le 1\text{pt}$ micro-fonts, `<w:vanish/>`, PDF `3 Tr` invisible text), Unicode smuggling (Trojan Source, Plane-14 tags), and encoded payloads before LLM or RAG ingestion.

Built with a pure **Rust** core (`crates/aegis-core`) for $O(n)$ ReDoS-safe regex scanning and bounded `16 MB` decompression, exposed to Python via **GIL-free `PyO3` (`maturin`)** bindings and a standalone native CLI binary.

---

## Architecture & Detection Rules

```text
Raw File (.docx / .pdf / .txt) ──▶ [SHA-256] ──▶ [Rust OOXML/PDF Unpack (16 MB cap)] ──▶ [O(n) Regex & Unicode] ──▶ Gate
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

### Python (`PyO3` Native Extension)

```bash
pip install maturin
python -m maturin build --release -o dist && pip install dist/*.whl

# Scan a directory or file (.docx, .pdf, .txt)
python -m aegis scan ./evidence_bundle/ --json --strict

# Sanitize and NFKC-normalize text
python -m aegis sanitize ./vendor_soc2_report.docx -o ./clean_extract.txt
```

```python
from aegis import sanitize_text, scan_file

report = scan_file("vendor_soc2_report.docx")
print(report.verdict, report.risk_score, report.sha256)

clean = sanitize_text("Audit log\u202e with hidden bidi override")
```

### Standalone Native Rust CLI

```bash
cargo build --release --bin aegis
./target/release/aegis scan ./vendor_soc2_report.docx --json --strict
```

---

## Scope & Limitations

- **Structural & Format Pre-Filter:** AEGIS catches deterministic format smuggling (`.docx` vanished/white text, `.pdf` invisible `3 Tr` streams, Unicode bidi/Plane-14 tags, and Base64 payloads). It complements—rather than replaces—semantic LLM guardrails for nuanced natural-language social engineering.
- **Safety Guarantees:** Rust's `regex` engine guarantees linear $O(n)$ scan time (no ReDoS backtracking), `quick-xml` avoids external XML entity expansion, and `flate2`/`zip` streams enforce a `16 MB` decompression cap.

---

## Running Tests

```bash
cargo test --workspace
python -m pytest -v
```
