# Ecosystem Audit: Top Public MCP Server Install Configs (Nov 2026)

To test `mcp-audit` on real-world defaults, we queried the top 80 most-starred public GitHub repositories matching `mcp server` (`stars > 1000`, non-archived) via the GitHub API on **2026-11-23**, extracted every parseable `mcpServers` / `servers` JSON installation snippet from their primary `README.md`, and audited each with `mcp-audit scan --format json`.

> **Note:** This study audits only publicly published `README.md` quick-start configuration snippets (not live servers). Flagging `MCP001` does not mean a repository is malicious—it highlights that copy-pasting the default unpinned `npx -y` / `uvx` snippet leaves users exposed to upstream package takeovers or silent tool-schema rug-pulls on next restart.

### Key Finding
- **12** top-starred repositories exposed parseable `mcpServers` / `servers` JSON install blocks in their primary `README.md`.
- **8 of 12 (66.7%)** triggered **`MCP001` (Unpinned ephemeral package runner)** — recommending `npx -y` or `uvx` without an exact immutable version pin.
- **4 of 12 (33.3%)** scored **Grade A (0 findings)** by using HTTPS endpoints, containers, or pinned/local executables.

### Per-Repository Breakdown (Snapshot: 2026-11-23)

| Repository | Stars | Grade | Risk Score | Rules Triggered |
| :--- | ---: | :---: | ---: | :--- |
| [DayuanJiang/next-ai-draw-io](https://github.com/DayuanJiang/next-ai-draw-io) | 37,144 | B | 15 | `MCP001` |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | 34,690 | A | 0 | None |
| [googleapis/mcp-toolbox](https://github.com/googleapis/mcp-toolbox) | 16,940 | B | 15 | `MCP001` |
| [GLips/Figma-Context-MCP](https://github.com/GLips/Figma-Context-MCP) | 16,287 | B | 15 | `MCP001` |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | 12,013 | B | 15 | `MCP001` |
| [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | 10,405 | B | 15 | `MCP001` |
| [awslabs/mcp](https://github.com/awslabs/mcp) | 9,943 | B | 15 | `MCP001` |
| [idosal/git-mcp](https://github.com/idosal/git-mcp) | 8,533 | A | 0 | None |
| [irinabuht12-oss/google-ads-meta-ads-mcp](https://github.com/irinabuht12-oss/google-ads-meta-ads-mcp) | 8,318 | A | 0 | None |
| [sooperset/mcp-atlassian](https://github.com/sooperset/mcp-atlassian) | 6,146 | B | 15 | `MCP001` |
| [makenotion/notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | 4,720 | B | 15 | `MCP001` |
| [MarkusPfundstein/mcp-obsidian](https://github.com/MarkusPfundstein/mcp-obsidian) | 4,550 | A | 0 | None |

### Recommended Hardening
1. **Pin exact versions** in `npx`/`uvx` commands (e.g., `@scope/pkg@1.2.3` or `pkg==1.2.3`).
2. **Lock live tool schemas** with `mcp-audit pin .cursor/mcp.json --probe` and run `mcp-audit verify --probe` in CI so any silent post-install description mutation (`RUG001`) fails the build.
