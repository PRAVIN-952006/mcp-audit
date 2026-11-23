import * as crypto from "node:crypto";
import type {
  Finding,
  Lockfile,
  LockfileServerPin,
  McpServerConfig,
  McpToolDefinition,
  ParsedMcpSource,
  RuleMetadata,
} from "./types.ts";

export const RUGPULL_RULES: RuleMetadata[] = [
  {
    id: "RUG001",
    severity: "CRITICAL",
    category: "rug-pull",
    title: "Tool schema or description mutated since pin (rug-pull)",
    summary: "SHA-256 hash of a tool's name/description/inputSchema differs from the pinned lockfile.",
  },
  {
    id: "RUG002",
    severity: "HIGH",
    category: "rug-pull",
    title: "Unpinned new tool added to server",
    summary: "A server now exposes a tool that was not present when the lockfile was created.",
  },
  {
    id: "RUG003",
    severity: "HIGH",
    category: "rug-pull",
    title: "Server command, arguments, or URL changed since pin",
    summary: "The execution command, arguments, or endpoint URL of a pinned server has drifted.",
  },
  {
    id: "RUG004",
    severity: "MEDIUM",
    category: "rug-pull",
    title: "Previously pinned server or tool was removed",
    summary: "A server or tool recorded in the lockfile is no longer present.",
  },
];

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${pairs.join(",")}}`;
}

export function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

export function hashTool(tool: McpToolDefinition): string {
  return sha256Hex(
    canonicalJson({
      name: tool.name,
      description: tool.description ?? "",
      inputSchema: tool.inputSchema ?? null,
      annotations: tool.annotations ?? null,
    })
  );
}

export function hashServerConfig(cfg: McpServerConfig): string {
  // Deliberately hash ONLY env key names (never secret values) so lockfiles are safe to commit in Git.
  return sha256Hex(
    canonicalJson({
      command: cfg.command ?? null,
      args: cfg.args ?? [],
      url: cfg.url ?? null,
      transport: cfg.transport ?? null,
      envKeys: cfg.env ? Object.keys(cfg.env).sort() : [],
      headerKeys: cfg.headers ? Object.keys(cfg.headers).sort() : [],
    })
  );
}

export function buildLockfile(sources: ParsedMcpSource[], toolVersion: string): Lockfile {
  const servers: Record<string, LockfileServerPin> = {};

  const ensureServer = (name: string, cfg?: McpServerConfig): LockfileServerPin => {
    const existing = servers[name];
    if (existing) return existing;
    const pin: LockfileServerPin = {
      configSha256: cfg ? hashServerConfig(cfg) : sha256Hex("{}"),
      envKeys: cfg?.env ? Object.keys(cfg.env).sort() : [],
      tools: {},
    };
    if (cfg?.command !== undefined) pin.command = cfg.command;
    if (cfg?.args !== undefined) pin.args = cfg.args;
    if (cfg?.url !== undefined) pin.url = cfg.url;
    servers[name] = pin;
    return pin;
  };

  for (const src of sources) {
    for (const [name, cfg] of Object.entries(src.servers)) {
      const pin = ensureServer(name, cfg);
      if (cfg.tools) {
        for (const t of cfg.tools) {
          pin.tools[t.name] = {
            sha256: hashTool(t),
            descriptionLength: t.description?.length ?? 0,
          };
        }
      }
    }
    for (const group of src.standaloneTools) {
      const pin = ensureServer(group.server);
      for (const t of group.tools) {
        pin.tools[t.name] = {
          sha256: hashTool(t),
          descriptionLength: t.description?.length ?? 0,
        };
      }
    }
  }

  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    toolVersion,
    servers,
  };
}

export function verifyAgainstLockfile(
  sources: ParsedMcpSource[],
  lockfile: Lockfile,
  lockfilePath: string
): Finding[] {
  const findings: Finding[] = [];
  const current = buildLockfile(sources, lockfile.toolVersion);

  for (const [serverName, currPin] of Object.entries(current.servers)) {
    const expectedPin = lockfile.servers[serverName];
    if (!expectedPin) {
      findings.push({
        ruleId: "RUG002",
        severity: "HIGH",
        category: "rug-pull",
        title: `Unpinned new MCP server "${serverName}"`,
        message: `Server "${serverName}" is not present in lockfile ${lockfilePath}.`,
        source: lockfilePath,
        server: serverName,
        evidence: `new server "${serverName}" (config=${currPin.configSha256.slice(0, 12)})`,
        remediation: `Audit the new server and regenerate the lockfile with "mcp-audit pin" if approved.`,
      });
      continue;
    }

    if (currPin.configSha256 !== expectedPin.configSha256) {
      findings.push({
        ruleId: "RUG003",
        severity: "HIGH",
        category: "rug-pull",
        title: `Server configuration drifted for "${serverName}"`,
        message: `Command, arguments, URL, or env keys for server "${serverName}" changed since lockfile pin.`,
        source: lockfilePath,
        server: serverName,
        evidence: `expected=${expectedPin.configSha256.slice(0, 12)} actual=${currPin.configSha256.slice(0, 12)}`,
        remediation: `Diff the MCP config change and re-pin only after verifying the new command or endpoint.`,
      });
    }

    for (const [toolName, currTool] of Object.entries(currPin.tools)) {
      const expectedTool = expectedPin.tools[toolName];
      if (!expectedTool) {
        findings.push({
          ruleId: "RUG002",
          severity: "HIGH",
          category: "rug-pull",
          title: `Unpinned new tool "${toolName}" on "${serverName}"`,
          message: `Tool "${toolName}" appeared on server "${serverName}" after the lockfile was pinned.`,
          source: lockfilePath,
          server: serverName,
          tool: toolName,
          evidence: `new tool hash=${currTool.sha256.slice(0, 12)}`,
          remediation: `Inspect the new tool schema for poisoning before re-pinning.`,
        });
      } else if (currTool.sha256 !== expectedTool.sha256) {
        findings.push({
          ruleId: "RUG001",
          severity: "CRITICAL",
          category: "rug-pull",
          title: `Rug-pull mutation detected on tool "${toolName}"`,
          message: `Tool "${toolName}" on server "${serverName}" changed its description or inputSchema hash after pinning (len ${expectedTool.descriptionLength} -> ${currTool.descriptionLength}).`,
          source: lockfilePath,
          server: serverName,
          tool: toolName,
          evidence: `expected=${expectedTool.sha256.slice(0, 12)} actual=${currTool.sha256.slice(0, 12)}`,
          remediation: `Block execution immediately and inspect the diff for silently injected instructions.`,
        });
      }
    }

    for (const oldTool of Object.keys(expectedPin.tools)) {
      if (!currPin.tools[oldTool]) {
        findings.push({
          ruleId: "RUG004",
          severity: "MEDIUM",
          category: "rug-pull",
          title: `Pinned tool "${oldTool}" removed from "${serverName}"`,
          message: `Tool "${oldTool}" was in the lockfile for "${serverName}" but is no longer exposed.`,
          source: lockfilePath,
          server: serverName,
          tool: oldTool,
          remediation: `Confirm the tool removal was intentional and update the lockfile.`,
        });
      }
    }
  }

  for (const oldServer of Object.keys(lockfile.servers)) {
    if (!current.servers[oldServer]) {
      findings.push({
        ruleId: "RUG004",
        severity: "MEDIUM",
        category: "rug-pull",
        title: `Pinned server "${oldServer}" removed`,
        message: `Server "${oldServer}" was in ${lockfilePath} but is no longer present in the scanned configs.`,
        source: lockfilePath,
        server: oldServer,
        remediation: `Update the lockfile with "mcp-audit pin" if removal was intentional.`,
      });
    }
  }

  return findings;
}
