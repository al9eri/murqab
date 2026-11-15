<p align="left">
  <img src="./assets/murqab-icon.svg" width="52" height="52" alt="murqab icon" align="left" style="margin-right: 14px;" />
</p>

# murqab

[![CI](https://github.com/al9eri/murqab/actions/workflows/ci.yml/badge.svg)](https://github.com/al9eri/murqab/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

*Al Murqab (المرقب)* is an Emirati watchtower. This is a fast Rust + Python (`PyO3`) security proxy for MCP servers and untrusted documents.

I built it because LLMs ingest `.docx` files, PDFs, and third-party MCP tool outputs blindly. Most scanners only check plain JSON text and miss Word `<w:vanish/>` runs, PDF `3 Tr` invisible text streams, `tools/list` poisoning, mid-session tool rug-pulls, or secrets sneaking back out in tool arguments. Everything runs locally in Rust at ~55 µs per 10 KB doc with no LLM-judge latency.

## How it sits in the loop

```text
Agent Client ──▶ [Outbound: Egress DLP (-32003) + Taint Sink Guard (-32002)] ──▶ MCP Server
Agent Client ◀── [Inbound: SHA-256 Tool Pinning + .docx/.pdf/Prompt Scan (-32001)] ◀── MCP Server
```

### What it catches

- **Tool manifests & rug-pulls (`MURQAB-MCP-007`, `MURQAB-MCP-008`):** Flags `<IMPORTANT>` / hidden instructions in `tools/list`, and SHA-256 pins each tool's description and `inputSchema` so mid-session mutations get blocked.
- **Session taint & egress DLP (`MURQAB-SEC-001`):** Any flagged server response taints the session and blocks follow-up sensitive sinks (`bash`, `write_file`, `http_post`, `send_email`, etc.) with `-32002`. Outbound `tools/call` arguments carrying live AWS (`AKIA...`), GitHub (`ghp_...`), Anthropic/OpenAI (`sk-...`), or PEM private keys are blocked immediately with `-32003`, even on untainted sessions.
- **Hidden document text (`MURQAB-DOC-001`, `MURQAB-PDF-001`):** Unpacks `.docx` (`<w:vanish/>`, `<w:webHidden/>`, `<= 1pt` micro-text, `#FFFFFF` runs) and decompressed PDF `/FlateDecode` streams (`3 Tr`, `1 1 1 rg`, `/JavaScript`), capped at 16 MB per archive.
- **Stealth Unicode & injections (`MURQAB-UNI-*`, `MURQAB-INJ-*`, `MURQAB-GRC-003`, `MURQAB-EXF-004`, `MURQAB-TOOL-005`, `MURQAB-MCP-006`, `MURQAB-ENC-001`):** Catches Trojan Source bidi overrides, Plane-14 tag smuggling, zero-width clusters, HTML comments, chat-template boundary spoofing, Base64-wrapped payloads, and cross-tool hijacks (`~/.ssh`, `.env`).

## Usage

### 1. Drop-in MCP `stdio` proxy

Wrap any third-party MCP server in Claude Desktop, Cursor, or Windsurf:

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

- `--mode block`: returns JSON-RPC `-32001` when an inbound manifest, rug-pull, or payload trips a rule.
- `--mode sanitize` (default): strips stealth Unicode, scrubs secrets to `[REDACTED_SECRET]`, wraps flagged strings in `<untrusted_tool_output>`, and taints the session (`-32002` / `-32003` outbound).

### 2. Python `@guard_tool` & file scanning

```python
from murqab import guard_tool, sanitize_text, scan_file

@guard_tool(mode="block")
def fetch_vendor_notes(url: str) -> str:
    ...

report = scan_file("vendor_soc2_report.docx")
print(report.verdict, report.risk_score, report.sha256)
```

## Kill-chain demo & benchmark

```bash
cargo build --release --bin murqab
python examples/mcp_poison_demo.py
```

Running on Windows x86_64 (Python 3.13 + Rust `PyO3` release build):
- **Stage 1 (`tools/list` poisoning):** Blocked with `-32001` (`MURQAB-MCP-006`, `MURQAB-MCP-007`).
- **Stage 2 (Mid-session rug-pull):** Clean `tools/list` pinned via SHA-256; mutated schema on call #2 blocked with `-32001` (`MURQAB-MCP-008`).
- **Stage 3 & 4a (Taint tracking):** Poisoned `resources/read` sanitized and session marked tainted; follow-up `bash` call blocked with `-32002`.
- **Stage 4b (Egress DLP):** Untainted `get_weather` call carrying `AKIAIOSFODNN7EXAMPLE` blocked with `-32003` (`MURQAB-SEC-001`).
- **Throughput:** 1,000 x 9.9 KB (`9900B`) documents scanned in **55.22 ms** (**0.0552 ms/doc** / ~55 µs).

## Notes

`murqab` is a fast deterministic pre-filter built on Rust's linear-time `regex` engine and `quick-xml` (no external entity expansion). It catches structural smuggling, pinned schema drift, and secret leaks before data hits the model; pair it with semantic guardrails if you need natural-language social-engineering detection.
