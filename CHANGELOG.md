# Changelog

All notable changes to `mcp-audit` are documented in this file.

## [0.3.0] - 2026-11-23
### Added
- **Live Streamable-HTTP / SSE probing (`probeHttpServer`):** Supports remote MCP servers via JSON-RPC 2.0 `initialize` -> `Mcp-Session-Id` -> `tools/list`, parsing both `application/json` and `text/event-stream` SSE frames.
- **Reusable GitHub Action (`action.yml`):** Composite action supporting `path`, `probe`, `lockfile`, `fail-on`, and `sarif-file` inputs for GitHub Code Scanning.
- **Visual terminal demo (`assets/demo.svg`)** embedded in `README.md`.
- **Hardened reference config (`examples/hardened-mcp.json`)** and `CONTRIBUTING.md`.

## [0.2.0] - 2026-11-23
### Added
- **Live stdio JSON-RPC 2.0 probing (`mcp-audit probe` / `--probe`):** Spawns local stdio MCP servers with a strict timeout, fetches live `tools/list` definitions, and audits them for poisoning, steganography, and rug-pull drift.
- End-to-end live stdio mock MCP server test.

## [0.1.0] - 2026-11-23
### Added
- Zero-dependency TypeScript CLI and library (`"dependencies": {}`).
- 20 security rules: `MCP001`–`MCP008` (static config), `TOOL001`–`TOOL008` (tool poisoning, Unicode Tag steganography decoding, shadowing, schema checks), and `RUG001`–`RUG004` (SHA-256 canonical-JSON rug-pull lockfile).
- Auto-discovery for Claude Desktop, Cursor, VS Code, Claude Code, and Windsurf.
- Text, JSON, and SARIF 2.1.0 reporters.
