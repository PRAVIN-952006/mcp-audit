import { BLOCKED_OVERRIDE_ENV_KEYS } from "./probe.ts";
import type { McpServerConfig, McpToolDefinition } from "./types.ts";

export interface HardenChange {
  server: string;
  field: string;
  action: string;
}

export interface HardenResult {
  hardenedJson: string;
  changes: HardenChange[];
}

const SECRET_VALUE_REGEX =
  /(?:\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_live_[A-Za-z0-9]{16,}\b|\bAIza[0-9A-Za-z_-]{35}\b|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._-]{20,}\b)/i;

const SENSITIVE_KEY_REGEX = /(?:SECRET|TOKEN|API[_-]?KEY|PASSWORD|PASSWD|PRIVATE[_-]?KEY|AUTH|CREDENTIAL)/i;
const PLACEHOLDER_REGEX = /^(?:\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|<[^>]+>|YOUR[_-]?.*|REPLACE[_-]?.*)$/i;
const DANGEROUS_ENV_KEYS = new Set(
  [...BLOCKED_OVERRIDE_ENV_KEYS].filter((k) => k !== "PATH" && k !== "NODE_TLS_REJECT_UNAUTHORIZED")
);

function stripInvisibleUnicode(text: string): { cleaned: string; removed: number } {
  let removed = 0;
  const out: string[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    const isTag = cp >= 0xe0000 && cp <= 0xe007f;
    const isBidi = (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
    const isZw = (cp >= 0x200b && cp <= 0x200f) || cp === 0x2060 || cp === 0xfeff;
    if (isTag || isBidi || isZw) {
      removed++;
    } else {
      out.push(ch);
    }
  }
  return { cleaned: out.join(""), removed };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hardenServerMap(servers: Record<string, unknown>, changes: HardenChange[]): void {
  for (const [serverName, rawCfg] of Object.entries(servers)) {
    if (!isRecord(rawCfg)) continue;
    const cfg = rawCfg as McpServerConfig & Record<string, unknown>;

    // 1. Replace hardcoded secrets in env with ${KEY} references & remove dangerous loader overrides
    if (isRecord(cfg.env)) {
      const env = cfg.env as Record<string, string>;
      for (const [k, v] of Object.entries(env)) {
        if (typeof v !== "string") continue;
        const trimmed = v.trim();
        if (DANGEROUS_ENV_KEYS.has(k.toUpperCase())) {
          delete env[k];
          changes.push({ server: serverName, field: `env.${k}`, action: `Removed dangerous loader override ${k}` });
          continue;
        }
        if (k.toUpperCase() === "NODE_TLS_REJECT_UNAUTHORIZED" && trimmed === "0") {
          delete env[k];
          changes.push({
            server: serverName,
            field: "env.NODE_TLS_REJECT_UNAUTHORIZED",
            action: "Removed NODE_TLS_REJECT_UNAUTHORIZED=0 (restored TLS verification)",
          });
          continue;
        }
        if (
          trimmed &&
          !PLACEHOLDER_REGEX.test(trimmed) &&
          (SECRET_VALUE_REGEX.test(trimmed) || (SENSITIVE_KEY_REGEX.test(k) && trimmed.length >= 12))
        ) {
          env[k] = `\${${k}}`;
          changes.push({
            server: serverName,
            field: `env.${k}`,
            action: `Replaced hardcoded secret with environment reference \${${k}}`,
          });
        }
      }
    }

    // 2. Replace hardcoded secrets in HTTP headers
    if (isRecord(cfg.headers)) {
      const headers = cfg.headers as Record<string, string>;
      for (const [k, v] of Object.entries(headers)) {
        if (typeof v !== "string") continue;
        const trimmed = v.trim();
        if (
          trimmed &&
          !PLACEHOLDER_REGEX.test(trimmed) &&
          (SECRET_VALUE_REGEX.test(trimmed) || (SENSITIVE_KEY_REGEX.test(k) && trimmed.length >= 12))
        ) {
          const envKey = k.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
          headers[k] = trimmed.toLowerCase().startsWith("bearer ") ? `Bearer \${${envKey}}` : `\${${envKey}}`;
          changes.push({
            server: serverName,
            field: `headers.${k}`,
            action: `Replaced hardcoded header credential with \${${envKey}}`,
          });
        }
      }
    }

    // 3. Remove wildcard autoApprove
    if (Array.isArray(cfg.autoApprove)) {
      const filtered = cfg.autoApprove.filter((t) => t !== "*" && t !== "all");
      if (filtered.length !== cfg.autoApprove.length) {
        cfg.autoApprove = filtered;
        changes.push({
          server: serverName,
          field: "autoApprove",
          action: "Removed wildcard autoApprove entries",
        });
      }
    }

    // 4. Strip dangerous sandbox-bypass flags
    if (Array.isArray(cfg.args)) {
      const bypassFlags = new Set(["--allow-all", "--dangerously-skip-permissions", "--no-sandbox", "--yolo"]);
      const filtered = cfg.args.filter((a) => !bypassFlags.has(a));
      if (filtered.length !== cfg.args.length) {
        cfg.args = filtered;
        changes.push({
          server: serverName,
          field: "args",
          action: "Removed sandbox-bypass CLI flags",
        });
      }
    }

    // 5. Strip invisible Unicode Tag / bidi / zero-width steganography from inline tool schemas
    if (Array.isArray(cfg.tools)) {
      for (const tool of cfg.tools as McpToolDefinition[]) {
        if (typeof tool.name === "string") {
          const { cleaned, removed } = stripInvisibleUnicode(tool.name);
          if (removed > 0) {
            tool.name = cleaned;
            changes.push({
              server: serverName,
              field: `tools.${tool.name}.name`,
              action: `Stripped ${removed} invisible Unicode steganography character(s)`,
            });
          }
        }
        if (typeof tool.description === "string") {
          const { cleaned, removed } = stripInvisibleUnicode(tool.description);
          if (removed > 0) {
            tool.description = cleaned;
            changes.push({
              server: serverName,
              field: `tools.${tool.name}.description`,
              action: `Stripped ${removed} invisible Unicode steganography character(s)`,
            });
          }
        }
        if (isRecord(tool.inputSchema) && isRecord(tool.inputSchema["properties"])) {
          for (const [propName, propVal] of Object.entries(tool.inputSchema["properties"])) {
            if (isRecord(propVal) && typeof propVal["description"] === "string") {
              const { cleaned, removed } = stripInvisibleUnicode(propVal["description"]);
              if (removed > 0) {
                propVal["description"] = cleaned;
                changes.push({
                  server: serverName,
                  field: `tools.${tool.name}.inputSchema.properties.${propName}.description`,
                  action: `Stripped ${removed} invisible Unicode steganography character(s)`,
                });
              }
            }
          }
        }
      }
    }
  }
}

export function hardenMcpJsonContent(rawText: string): HardenResult {
  const parsed: unknown = JSON.parse(rawText);
  if (!isRecord(parsed)) {
    throw new Error("Expected a JSON object in MCP config");
  }
  const changes: HardenChange[] = [];
  if (isRecord(parsed["mcpServers"])) {
    hardenServerMap(parsed["mcpServers"], changes);
  }
  if (isRecord(parsed["servers"])) {
    hardenServerMap(parsed["servers"], changes);
  }
  return {
    hardenedJson: `${JSON.stringify(parsed, null, 2)}\n`,
    changes,
  };
}
