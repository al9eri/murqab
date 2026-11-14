<p align="left">
  <img src="./assets/murqab-icon.svg" width="52" height="52" alt="murqab icon" align="left" style="margin-right: 14px;" />
</p>

# murqab

[![CI](https://github.com/al9eri/murqab/actions/workflows/ci.yml/badge.svg)](https://github.com/al9eri/murqab/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

*Al Murqab (المرقب)* — traditional Emirati watchtower.  
Rust-accelerated **MCP `stdio` security proxy (`murqab mcp-proxy`)**, document scanner, and Python `@guard_tool` decorator for intercepting indirect prompt injections, cross-tool hijacks, hidden `.docx` / `.pdf` stealth text layers, and Unicode smuggling in **`~57 µs` per 10 KB document**.

Built on a pure **Rust** core (`crates/murqab-core`) with guaranteed $O(n)$ ReDoS-safe regex matching and bounded `16 MB` archive decompression, exposed via **GIL-free `PyO3` (`maturin`)** bindings and a standalone native CLI binary.

---

## Architecture & Detection Rules

```text
Untrusted MCP Server / File (.docx, .pdf, .txt) ──▶ [murqab Rust Core (~57 µs)] ──▶ Block (-32001) or Sanitize
```

| Rule ID | Category | Severity | Vector Addressed |
| :--- | :--- | :--- | :--- |
| `MURQAB-MCP-006` | `cross_tool_hijack` | `CRITICAL` | Instructions coercing agents to read `~/.ssh` / `.env` / secrets or invoke secondary shell/email tools. |
| `MURQAB-INJ-003` | `html_comment_smuggling` | `HIGH` | Hidden HTML/Markdown comments (`<!-- ... ignore/execute/exfiltrate ... -->`) in scraped docs & issues. |
| `MURQAB-DOC-001` | `hidden_document_text` | `CRITICAL` | OOXML (`.docx`) stealth runs: `<w:vanish/>`, `<w:webHidden/>`, $\le 1\text{pt}$ micro-fonts, or white text (`#FFFFFF`). |
| `MURQAB-PDF-001` | `pdf_stealth_layer` | `CRITICAL` | Decompressed PDF `/FlateDecode` streams using `3 Tr` invisible text, `1 1 1 rg` white fill, or `/JavaScript` actions. |
| `MURQAB-UNI-001` | `trojan_bidi` | `CRITICAL` | Unicode bidirectional overrides (`U+202A–U+202E`, `U+2066–U+2069` — CVE-2021-42574 Trojan Source). |
| `MURQAB-UNI-002` | `unicode_tag_smuggling` | `CRITICAL` | Invisible Plane-14 Unicode Tag characters (`U+E0000–U+E007F`). |
| `MURQAB-UNI-003` | `zero_width_obfuscation` | `MEDIUM` | Clusters of zero-width spaces/joiners (`U+200B–U+200D`, `U+2060`). |
| `MURQAB-INJ-001` | `boundary_spoofing` | `CRITICAL` | Chat-template & system-role delimiters (`<\|im_start\|>system`, `[INST]`, `<<SYS>>`). |
| `MURQAB-INJ-002` | `instruction_override` | `HIGH` | Explicit instruction-override directives (`ignore previous instructions/guardrails/controls`). |
| `MURQAB-GRC-003` | `verdict_manipulation` | `CRITICAL` | Coercive audit-status overrides (`mark all controls as compliant / certified / approved`). |
| `MURQAB-EXF-004` | `markdown_exfiltration` | `HIGH` | Markdown image beacons (`![...](https://...?secret=...)`) exfiltrating context at render time. |
| `MURQAB-TOOL-005` | `tool_hijack` | `HIGH` | Embedded shell/tool execution triggers (`execute_command`, `run_shell`, `curl`). |
| `MURQAB-ENC-001` | `encoded_payload` | `HIGH` | Base64-encoded prompt-injection payloads hidden inside logs or JSON fields. |

---

## Quick Start

### 1. Drop-In MCP `stdio` Firewall Proxy (Claude Desktop / Cursor / Windsurf)

Wrap any untrusted third-party MCP server without modifying a line of its code:

```json
{
  "mcpServers": {
    "fetch": {
      "command": "murqab",
      "args": ["mcp-proxy", "--mode", "block", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    }
  }
}
```

- `--mode block`: Returns a JSON-RPC `-32001` security error naming triggered rule IDs if an injection is detected.
- `--mode sanitize` *(default)*: Strips hidden Unicode/bidi characters and wraps tainted strings in `<untrusted_tool_output>` tags.

### 2. Python Agent `@guard_tool` & File Scanning (`PyO3`)

```python
from murqab import guard_tool, sanitize_text, scan_file

@guard_tool(mode="block")
def fetch_vendor_notes(url: str) -> str:
    ...

report = scan_file("vendor_soc2_report.docx")
print(report.verdict, report.risk_score, report.sha256)
```

---

## Reproducible Demo & Verified Benchmark

```bash
cargo build --release --bin murqab
python examples/mcp_poison_demo.py
```

Observed output (Windows x86_64, Python 3.13 + Rust `PyO3` release build):
- **Live `mcp-proxy --mode block`:** Intercepted 4 rules (`MURQAB-INJ-002`, `MURQAB-INJ-003`, `MURQAB-MCP-006`, `MURQAB-UNI-002`) $\rightarrow$ returned `-32001` JSON-RPC block.
- **Throughput:** `1,000 × 9.9 KB` documents scanned in **`56.88 ms`** (**`0.0569 ms/doc`** / **`~57 µs`**).

---

## Scope & Limitations

- **Deterministic Pre-Filter:** Catches structural smuggling (`.docx` vanished/white text, `.pdf` `3 Tr` streams, MCP HTML comments, cross-tool credential reads, Unicode bidi/Plane-14 tags, Base64 payloads). It complements—rather than replaces—semantic LLM guardrails for nuanced natural-language social engineering.
- **Safety Guarantees:** Rust's `regex` engine enforces $O(n)$ scan time (immune to ReDoS), `quick-xml` avoids external XML entity expansion, and `flate2`/`zip` enforce a `16 MB` decompression cap.
