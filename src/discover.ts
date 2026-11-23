import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { McpServerConfig, McpToolDefinition, ParsedMcpSource } from "./types.ts";

export interface DiscoveryCandidate {
  clientHint: string;
  filePath: string;
}

export function getDefaultDiscoveryCandidates(cwd: string = process.cwd()): DiscoveryCandidate[] {
  const home = os.homedir();
  const appData = process.env["APPDATA"] ?? path.join(home, "AppData", "Roaming");

  const candidates: DiscoveryCandidate[] = [
    // Project-local MCP configs
    { clientHint: "Project (.mcp.json)", filePath: path.join(cwd, ".mcp.json") },
    { clientHint: "Cursor (Project)", filePath: path.join(cwd, ".cursor", "mcp.json") },
    { clientHint: "VS Code (Project)", filePath: path.join(cwd, ".vscode", "mcp.json") },
    // User-global MCP configs (macOS / Linux / Windows)
    {
      clientHint: "Claude Desktop (macOS)",
      filePath: path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    },
    {
      clientHint: "Claude Desktop (Linux)",
      filePath: path.join(home, ".config", "Claude", "claude_desktop_config.json"),
    },
    {
      clientHint: "Claude Desktop (Windows)",
      filePath: path.join(appData, "Claude", "claude_desktop_config.json"),
    },
    { clientHint: "Claude Code", filePath: path.join(home, ".claude.json") },
    { clientHint: "Cursor (Global)", filePath: path.join(home, ".cursor", "mcp.json") },
    {
      clientHint: "VS Code (macOS)",
      filePath: path.join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
    },
    {
      clientHint: "VS Code (Linux)",
      filePath: path.join(home, ".config", "Code", "User", "mcp.json"),
    },
    {
      clientHint: "Windsurf",
      filePath: path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    },
  ];

  const seen = new Set<string>();
  return candidates.filter((c) => {
    const resolved = path.resolve(c.filePath);
    if (seen.has(resolved)) return false;
    seen.add(resolved);
    return fs.existsSync(resolved);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeServerConfig(raw: Record<string, unknown>): McpServerConfig {
  const cfg: McpServerConfig = {};
  if (typeof raw["command"] === "string") cfg.command = raw["command"];
  if (Array.isArray(raw["args"])) {
    cfg.args = raw["args"].filter((a): a is string => typeof a === "string");
  }
  if (isRecord(raw["env"])) {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw["env"])) {
      env[k] = typeof v === "string" ? v : String(v);
    }
    cfg.env = env;
  }
  if (typeof raw["url"] === "string") cfg.url = raw["url"];
  if (typeof raw["serverUrl"] === "string" && !cfg.url) cfg.url = raw["serverUrl"];
  if (isRecord(raw["headers"])) {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw["headers"])) {
      headers[k] = typeof v === "string" ? v : String(v);
    }
    cfg.headers = headers;
  }
  if (typeof raw["transport"] === "string") cfg.transport = raw["transport"];
  if (typeof raw["type"] === "string" && !cfg.transport) cfg.transport = raw["type"];
  if (Array.isArray(raw["autoApprove"])) {
    cfg.autoApprove = raw["autoApprove"].filter((a): a is string => typeof a === "string");
  }
  if (typeof raw["disabled"] === "boolean") cfg.disabled = raw["disabled"];
  if (Array.isArray(raw["tools"])) {
    cfg.tools = normalizeTools(raw["tools"]);
  }
  return cfg;
}

function normalizeTools(rawTools: unknown[]): McpToolDefinition[] {
  const out: McpToolDefinition[] = [];
  for (const item of rawTools) {
    if (!isRecord(item) || typeof item["name"] !== "string") continue;
    const def: McpToolDefinition = { name: item["name"] };
    if (typeof item["description"] === "string") def.description = item["description"];
    if (isRecord(item["inputSchema"])) {
      def.inputSchema = item["inputSchema"] as McpToolDefinition["inputSchema"];
    }
    if (isRecord(item["annotations"])) {
      def.annotations = item["annotations"];
    }
    out.push(def);
  }
  return out;
}

export function parseMcpJsonContent(
  rawText: string,
  sourcePath: string,
  clientHint = "Custom"
): ParsedMcpSource {
  const parsed: unknown = JSON.parse(rawText);
  if (!isRecord(parsed)) {
    throw new Error(`Expected JSON object in ${sourcePath}`);
  }

  const servers: Record<string, McpServerConfig> = {};
  const standaloneTools: Array<{ server: string; tools: McpToolDefinition[] }> = [];

  // Standard Claude/Cursor/Windsurf/VS Code server maps
  const serverMaps: unknown[] = [parsed["mcpServers"], parsed["servers"]];

  // Claude Code ~/.claude.json also stores per-project mcpServers under projects[path].mcpServers
  if (isRecord(parsed["projects"])) {
    for (const [projPath, projVal] of Object.entries(parsed["projects"])) {
      if (isRecord(projVal) && isRecord(projVal["mcpServers"])) {
        for (const [name, srv] of Object.entries(projVal["mcpServers"])) {
          if (isRecord(srv)) {
            servers[`${path.basename(projPath)}:${name}`] = normalizeServerConfig(srv);
          }
        }
      }
    }
  }

  for (const map of serverMaps) {
    if (!isRecord(map)) continue;
    for (const [name, srv] of Object.entries(map)) {
      if (isRecord(srv)) {
        servers[name] = normalizeServerConfig(srv);
      }
    }
  }

  // Support standalone tools/list JSON snapshots: { "server": "...", "tools": [...] }
  if (Array.isArray(parsed["tools"])) {
    const serverName =
      typeof parsed["server"] === "string"
        ? parsed["server"]
        : path.basename(sourcePath, path.extname(sourcePath));
    const tools = normalizeTools(parsed["tools"]);
    if (tools.length > 0) {
      standaloneTools.push({ server: serverName, tools });
    }
  }

  return { sourcePath, clientHint, servers, standaloneTools };
}

export function loadMcpFile(filePath: string, clientHint = "Custom"): ParsedMcpSource {
  const resolved = path.resolve(filePath);
  const raw = fs.readFileSync(resolved, "utf8");
  return parseMcpJsonContent(raw, resolved, clientHint);
}
