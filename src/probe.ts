import { spawn } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import type { McpServerConfig, McpToolDefinition } from "./types.ts";

export interface ProbeResult {
  server: string;
  transport: "stdio" | "http";
  tools: McpToolDefinition[];
  protocolVersion?: string;
  error?: string;
}

export interface ProbeSecurityOptions {
  /** Allow probing RFC1918/private/metadata network endpoints over HTTP (default: false). */
  allowPrivateNetwork?: boolean;
  /** Maximum response/stdout bytes buffered before aborting (default: 4 MiB). */
  maxBytes?: number;
}

const DEFAULT_MAX_PROBE_BYTES = 4 * 1024 * 1024;
const PROBE_CLIENT_VERSION = "0.5.0";
const SAFE_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "TMPDIR",
  "TEMP",
  "TMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "SYSTEMROOT",
  "COMSPEC",
] as const;

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string;
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export const BLOCKED_OVERRIDE_ENV_KEYS = new Set([
  "PATH",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "LD_AUDIT",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  "DYLD_FALLBACK_LIBRARY_PATH",
  "NODE_OPTIONS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "PYTHONHOME",
  "PYTHONINSPECT",
  "BASH_ENV",
  "ENV",
  "RUBYOPT",
  "RUBYLIB",
  "PERL5OPT",
  "PERL5LIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "NPM_CONFIG_USERCONFIG",
  "GIT_SSH_COMMAND",
  "SSL_CERT_FILE",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "IFS",
]);

function buildSanitizedEnv(overrides?: Record<string, string>): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const key of SAFE_ENV_ALLOWLIST) {
    const val = process.env[key];
    if (typeof val === "string") safe[key] = val;
  }
  if (overrides) {
    for (const [k, v] of Object.entries(overrides)) {
      if (BLOCKED_OVERRIDE_ENV_KEYS.has(k.toUpperCase())) continue;
      safe[k] = v;
    }
  }
  return safe;
}

function extractMappedIpv4(ipv6Host: string): string | undefined {
  const sixToFour = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/.exec(ipv6Host);
  if (sixToFour) {
    const hi = Number.parseInt(sixToFour[1]!, 16);
    const lo = Number.parseInt(sixToFour[2]!, 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  let tail: string | undefined;
  if (ipv6Host.startsWith("::ffff:0:")) {
    tail = ipv6Host.slice(9);
  } else if (ipv6Host.startsWith("::ffff:")) {
    tail = ipv6Host.slice(7);
  } else if (ipv6Host.startsWith("64:ff9b::")) {
    tail = ipv6Host.slice(9);
  } else if (ipv6Host.startsWith("64:ff9b:1::")) {
    tail = ipv6Host.slice(11);
  } else if (ipv6Host.startsWith("::") && ipv6Host.length > 2) {
    tail = ipv6Host.slice(2);
  }
  if (!tail) return undefined;
  if (isIP(tail) === 4) return tail;
  const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
  if (!hexMatch) return undefined;
  const hi = Number.parseInt(hexMatch[1]!, 16);
  const lo = Number.parseInt(hexMatch[2]!, 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function isPrivateIpv4(ipv4: string): boolean {
  return (
    ipv4.startsWith("0.") ||
    ipv4.startsWith("127.") ||
    ipv4.startsWith("169.254.") ||
    ipv4.startsWith("10.") ||
    ipv4.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ipv4) ||
    /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./.test(ipv4)
  );
}

function checkIpAddress(ip: string, allowPrivateNetwork: boolean, requireValidIp = false): string | undefined {
  const noBrackets = ip.toLowerCase().replace(/^\[|\]$/g, "");
  const hasZone = noBrackets.includes("%");
  const normalized = (hasZone ? noBrackets.split("%")[0] : noBrackets) ?? "";
  const ipVersion = isIP(normalized);
  if (hasZone && ipVersion !== 6) {
    return `Blocked invalid scoped IP target: ${noBrackets}`;
  }
  if (requireValidIp && ipVersion === 0) {
    return `Blocked unparseable resolved IP address: ${noBrackets}`;
  }
  const mappedIpv4 = ipVersion === 6 ? extractMappedIpv4(normalized) : undefined;
  if (normalized === "169.254.169.254" || mappedIpv4 === "169.254.169.254") {
    return `Blocked cloud metadata endpoint: ${normalized}`;
  }
  if (!allowPrivateNetwork) {
    if (ipVersion === 4 && isPrivateIpv4(normalized)) {
      return `Blocked private/link-local/loopback probe target: ${normalized}`;
    }
    if (ipVersion === 6) {
      if (mappedIpv4 && isPrivateIpv4(mappedIpv4)) {
        return `Blocked private/link-local/loopback probe target: ${normalized}`;
      }
      if (
        normalized === "::" ||
        normalized === "::1" ||
        normalized.startsWith("fe80:") ||
        /^fe[89ab][0-9a-f]:/.test(normalized) ||
        /^f[cd][0-9a-f]{2}:/.test(normalized)
      ) {
        return `Blocked private/link-local/loopback probe target: ${normalized}`;
      }
    }
  }
  return undefined;
}

export function validateProbeUrl(rawUrl: string, allowPrivateNetwork: boolean): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return "Invalid probe URL";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return `Unsupported probe URL protocol: ${parsed.protocol}`;
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (host === "metadata.google.internal") {
    return `Blocked cloud metadata endpoint: ${host}`;
  }
  if (!allowPrivateNetwork && (host === "localhost" || host.endsWith(".localhost"))) {
    return `Blocked private/link-local/loopback probe target: ${host}`;
  }
  return checkIpAddress(host, allowPrivateNetwork);
}

interface ResolvedHostResult {
  error?: string;
  address?: string;
  family?: 4 | 6;
}

async function validateResolvedHost(rawUrl: string, allowPrivateNetwork: boolean): Promise<ResolvedHostResult> {
  const parsed = new URL(rawUrl);
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  const literalIp = isIP(host.split("%")[0] ?? "");
  if (literalIp !== 0) {
    return { address: host.split("%")[0], family: literalIp as 4 | 6 };
  }
  try {
    const records = await dnsLookup(host, { all: true, verbatim: true });
    if (records.length === 0) {
      return { error: `DNS resolution returned no addresses for ${host}` };
    }
    for (const rec of records) {
      const ipErr = checkIpAddress(rec.address, allowPrivateNetwork, true);
      if (ipErr) return { error: `${ipErr} (resolved from ${host})` };
    }
    const first = records[0]!;
    return { address: first.address, family: first.family === 6 ? 6 : 4 };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `DNS resolution failed for ${host}: ${msg}` };
  }
}

function pinnedHttpPost(
  rawUrl: string,
  headers: Record<string, string>,
  body: string,
  resolvedAddress: string,
  family: 4 | 6,
  signal: AbortSignal,
  maxBytes: number
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(rawUrl);
    const isHttps = parsed.protocol === "https:";
    const transport = isHttps ? https : http;
    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port ? Number(parsed.port) : isHttps ? 443 : 80,
        path: `${parsed.pathname}${parsed.search}`,
        method: "POST",
        headers: { ...headers, host: parsed.host },
        signal,
        ...(isHttps ? { servername: parsed.hostname } : {}),
        lookup: (_hostname, _opts, cb) => {
          cb(null, resolvedAddress, family);
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          res.resume();
          reject(new Error(`HTTP redirect blocked (${status})`));
          return;
        }
        const contentLength = res.headers["content-length"];
        if (contentLength && Number(contentLength) > maxBytes) {
          res.destroy();
          reject(new Error(`HTTP response exceeds max size limit (${maxBytes} bytes)`));
          return;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.byteLength;
          if (total > maxBytes) {
            res.destroy();
            reject(new Error(`HTTP response exceeds max size limit (${maxBytes} bytes)`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const responseHeaders = new Headers();
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") responseHeaders.set(k, v);
            else if (Array.isArray(v)) responseHeaders.set(k, v.join(", "));
          }
          resolve(new Response(Buffer.concat(chunks), { status, headers: responseHeaders }));
        });
        res.on("error", reject);
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

async function readResponseTextBounded(res: Response, maxBytes: number): Promise<string> {
  const contentLength = res.headers.get("content-length");
  if (contentLength && Number(contentLength) > maxBytes) {
    throw new Error(`HTTP response exceeds max size limit (${maxBytes} bytes)`);
  }
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error(`HTTP response exceeds max size limit (${maxBytes} bytes)`);
    }
    return text;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`HTTP response exceeds max size limit (${maxBytes} bytes)`);
      }
      chunks.push(value);
    }
  }
  return Buffer.concat(chunks).toString("utf8");
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
  fetchImpl: typeof fetch = fetch,
  securityOptions?: ProbeSecurityOptions
): Promise<ProbeResult> {
  if (!config.url) {
    return { server: serverName, transport: "http", tools: [], error: "No remote URL configured" };
  }

  const maxBytes = securityOptions?.maxBytes ?? DEFAULT_MAX_PROBE_BYTES;
  const allowPrivate = securityOptions?.allowPrivateNetwork ?? false;
  const urlError = validateProbeUrl(config.url, allowPrivate);
  if (urlError) {
    return { server: serverName, transport: "http", tools: [], error: urlError };
  }
  let resolvedPin: { address: string; family: 4 | 6 } | undefined;
  if (fetchImpl === fetch) {
    const dnsResult = await validateResolvedHost(config.url, allowPrivate);
    if (dnsResult.error) {
      return { server: serverName, transport: "http", tools: [], error: dnsResult.error };
    }
    if (dnsResult.address && dnsResult.family) {
      resolvedPin = { address: dnsResult.address, family: dnsResult.family };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const baseHeaders: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(config.headers ?? {}),
    };
    const postJson = (headers: Record<string, string>, payload: Record<string, unknown>): Promise<Response> => {
      const body = JSON.stringify(payload);
      if (resolvedPin) {
        return pinnedHttpPost(
          config.url!,
          headers,
          body,
          resolvedPin.address,
          resolvedPin.family,
          controller.signal,
          maxBytes
        );
      }
      return fetchImpl(config.url!, {
        method: "POST",
        headers,
        redirect: "error",
        signal: controller.signal,
        body,
      });
    };

    const initRes = await postJson(baseHeaders, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "mcp-audit", version: PROBE_CLIENT_VERSION },
      },
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
    const initText = await readResponseTextBounded(initRes, maxBytes);
    const initPayload = parseRpcPayload(initText, initRes.headers.get("content-type") ?? "");
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

    const listRes = await postJson(sessionHeaders, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });

    if (!listRes.ok) {
      return {
        server: serverName,
        transport: "http",
        tools: [],
        error: `HTTP ${listRes.status} on tools/list`,
      };
    }

    const listText = await readResponseTextBounded(listRes, maxBytes);
    const listPayload = parseRpcPayload(listText, listRes.headers.get("content-type") ?? "");
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
 * using newline-delimited JSON framing with a strict timeout, sanitized environment, and byte cap.
 */
export function probeStdioServer(
  serverName: string,
  config: McpServerConfig,
  timeoutMs = 5000,
  securityOptions?: ProbeSecurityOptions
): Promise<ProbeResult> {
  return new Promise((resolve) => {
    if (!config.command) {
      resolve({ server: serverName, transport: "stdio", tools: [], error: "No stdio command configured" });
      return;
    }

    const maxBytes = securityOptions?.maxBytes ?? DEFAULT_MAX_PROBE_BYTES;
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
      env: buildSanitizedEnv(config.env),
    });
    child.stderr.resume();

    const timer = setTimeout(() => {
      finish({ server: serverName, transport: "stdio", tools: [], error: `Timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    let buffer = "";
    let totalBytes = 0;
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
      totalBytes += Buffer.byteLength(chunk, "utf8");
      if (totalBytes > maxBytes) {
        finish({
          server: serverName,
          transport: "stdio",
          tools: [],
          error: `Stdio response exceeded max size limit (${maxBytes} bytes)`,
        });
        return;
      }
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
        clientInfo: { name: "mcp-audit", version: PROBE_CLIENT_VERSION },
      },
    });
  });
}
