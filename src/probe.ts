import { spawn } from "node:child_process";
import type { McpServerConfig, McpToolDefinition } from "./types.ts";

export interface ProbeResult {
  server: string;
  transport: "stdio" | "http";
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

function parseRpcPayload(text: string, contentType: string): JsonRpcResponse | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  if (contentType.includes("text/event-stream") || trimmed.startsWith("event:") || trimmed.startsWith("data:")) {
    for (const line of trimmed.split(/\r?\n/)) {
      if (line.startsWith("data:")) {
        const data = line.slice(5).trim();
        if (data.startsWith("{")) {
          try {
            return JSON.parse(data) as JsonRpcResponse;
          } catch {
            // continue scanning SSE frames
          }
        }
      }
    }
    return undefined;
  }
  return JSON.parse(trimmed) as JsonRpcResponse;
}

/**
 * Probes a remote Streamable-HTTP / SSE MCP server via JSON-RPC 2.0 (`initialize` -> `tools/list`).
 */
export async function probeHttpServer(
  serverName: string,
  config: McpServerConfig,
  timeoutMs = 5000,
  fetchImpl: typeof fetch = fetch
): Promise<ProbeResult> {
  if (!config.url) {
    return { server: serverName, transport: "http", tools: [], error: "No remote URL configured" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const baseHeaders: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(config.headers ?? {}),
    };

    const initRes = await fetchImpl(config.url, {
      method: "POST",
      headers: baseHeaders,
      signal: controller.signal,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "mcp-audit", version: "0.3.0" },
        },
      }),
    });

    if (!initRes.ok) {
      return {
        server: serverName,
        transport: "http",
        tools: [],
        error: `HTTP ${initRes.status} on initialize`,
      };
    }

    const sessionId = initRes.headers.get("mcp-session-id");
    const initPayload = parseRpcPayload(await initRes.text(), initRes.headers.get("content-type") ?? "");
    if (initPayload?.error) {
      return {
        server: serverName,
        transport: "http",
        tools: [],
        error: `initialize error: ${initPayload.error.message ?? "unknown"}`,
      };
    }

    const protocolVersion =
      initPayload?.result && typeof initPayload.result["protocolVersion"] === "string"
        ? initPayload.result["protocolVersion"]
        : undefined;

    const sessionHeaders: Record<string, string> = sessionId
      ? { ...baseHeaders, "mcp-session-id": sessionId }
      : baseHeaders;

    const listRes = await fetchImpl(config.url, {
      method: "POST",
      headers: sessionHeaders,
      signal: controller.signal,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      }),
    });

    if (!listRes.ok) {
      return {
        server: serverName,
        transport: "http",
        tools: [],
        error: `HTTP ${listRes.status} on tools/list`,
      };
    }

    const listPayload = parseRpcPayload(await listRes.text(), listRes.headers.get("content-type") ?? "");
    if (listPayload?.error) {
      return {
        server: serverName,
        transport: "http",
        tools: [],
        error: `tools/list error: ${listPayload.error.message ?? "unknown"}`,
      };
    }

    const tools = listPayload?.result ? extractToolsFromResult(listPayload.result) : [];
    return { server: serverName, transport: "http", tools, protocolVersion };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { server: serverName, transport: "http", tools: [], error: msg };
  } finally {
    clearTimeout(timer);
  }
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
      resolve({ server: serverName, transport: "stdio", tools: [], error: "No stdio command configured" });
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
      finish({ server: serverName, transport: "stdio", tools: [], error: `Timed out after ${timeoutMs}ms` });
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
            transport: "stdio",
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
            transport: "stdio",
            tools: [],
            error: `tools/list error: ${msg.error.message ?? "unknown"}`,
          });
          return;
        }
        const tools = msg.result ? extractToolsFromResult(msg.result) : [];
        finish({ server: serverName, transport: "stdio", tools, protocolVersion });
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
      finish({ server: serverName, transport: "stdio", tools: [], error: err.message });
    });

    child.on("exit", (code) => {
      if (!settled) {
        finish({
          server: serverName,
          transport: "stdio",
          tools: [],
          error: `Server exited early (code ${code ?? "null"})`,
        });
      }
    });

    sendRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-audit", version: "0.3.0" },
      },
    });
  });
}
