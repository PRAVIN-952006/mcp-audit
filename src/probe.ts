import { spawn } from "node:child_process";
import type { McpServerConfig, McpToolDefinition } from "./types.ts";

export interface ProbeResult {
  server: string;
  tools: McpToolDefinition[];
  protocolVersion?: string;
  error?: string;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string;
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function extractToolsFromResult(result: Record<string, unknown>): McpToolDefinition[] {
  const rawTools = result["tools"];
  if (!Array.isArray(rawTools)) return [];
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

/**
 * Probes a local stdio MCP server via standard JSON-RPC 2.0 (`initialize` -> `tools/list`)
 * using newline-delimited JSON framing with a strict timeout.
 */
export function probeStdioServer(
  serverName: string,
  config: McpServerConfig,
  timeoutMs = 5000
): Promise<ProbeResult> {
  return new Promise((resolve) => {
    if (!config.command) {
      resolve({ server: serverName, tools: [], error: "No stdio command configured" });
      return;
    }

    let settled = false;
    const finish = (res: ProbeResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill("SIGKILL");
      } catch {
        // already exited
      }
      resolve(res);
    };

    const child = spawn(config.command, config.args ?? [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...(config.env ?? {}) },
    });

    const timer = setTimeout(() => {
      finish({ server: serverName, tools: [], error: `Timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    let buffer = "";
    let protocolVersion: string | undefined;

    const sendRpc = (msg: Record<string, unknown>): void => {
      if (!child.stdin.destroyed) {
        child.stdin.write(`${JSON.stringify(msg)}\n`);
      }
    };

    const handleMessage = (msg: JsonRpcResponse): void => {
      if (msg.id === 1) {
        if (msg.error) {
          finish({
            server: serverName,
            tools: [],
            error: `initialize error: ${msg.error.message ?? "unknown"}`,
          });
          return;
        }
        if (msg.result && typeof msg.result["protocolVersion"] === "string") {
          protocolVersion = msg.result["protocolVersion"];
        }
        sendRpc({ jsonrpc: "2.0", method: "notifications/initialized" });
        sendRpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
      } else if (msg.id === 2) {
        if (msg.error) {
          finish({
            server: serverName,
            tools: [],
            error: `tools/list error: ${msg.error.message ?? "unknown"}`,
          });
          return;
        }
        const tools = msg.result ? extractToolsFromResult(msg.result) : [];
        finish({ server: serverName, tools, protocolVersion });
      }
    };

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      buffer += chunk;
      let nlIdx = buffer.indexOf("\n");
      while (nlIdx !== -1) {
        const line = buffer.slice(0, nlIdx).trim();
        buffer = buffer.slice(nlIdx + 1);
        if (line.startsWith("{")) {
          try {
            handleMessage(JSON.parse(line) as JsonRpcResponse);
          } catch {
            // ignore non-JSON log lines printed to stdout
          }
        }
        nlIdx = buffer.indexOf("\n");
      }
    });

    child.on("error", (err) => {
      finish({ server: serverName, tools: [], error: err.message });
    });

    child.on("exit", (code) => {
      if (!settled) {
        finish({ server: serverName, tools: [], error: `Server exited early (code ${code ?? "null"})` });
      }
    });

    sendRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-audit", version: "0.1.0" },
      },
    });
  });
}
