import type { Finding, McpServerConfig, RuleMetadata } from "../types.ts";

export const CONFIG_RULES: RuleMetadata[] = [
  {
    id: "MCP001",
    severity: "HIGH",
    category: "supply-chain",
    title: "Unpinned ephemeral package runner",
    summary: "Flags npx/uvx/bunx/pnpx/dlx invocations without an exact pinned package version.",
  },
  {
    id: "MCP002",
    severity: "CRITICAL",
    category: "secrets",
    title: "Hardcoded credential or API token in config",
    summary: "Detects live API keys, tokens, PEM blocks, or literal secrets in env or HTTP headers.",
  },
  {
    id: "MCP003",
    severity: "HIGH",
    category: "transport",
    title: "Insecure remote MCP transport",
    summary: "Flags unencrypted http:// remote endpoints or wildcard 0.0.0.0 exposure.",
  },
  {
    id: "MCP004",
    severity: "HIGH",
    category: "privilege",
    title: "Shell wrapper or piped remote execution",
    summary: "Detects sh/bash/cmd/powershell -c wrappers and curl|sh patterns in server commands.",
  },
  {
    id: "MCP005",
    severity: "HIGH",
    category: "privilege",
    title: "Over-privileged filesystem or credential path scope",
    summary: "Flags server arguments granting access to /, ~, /etc, ~/.ssh, ~/.aws, ~/.gnupg, or ~/.kube.",
  },
  {
    id: "MCP006",
    severity: "MEDIUM",
    category: "privilege",
    title: "Dangerous runtime environment override",
    summary: "Flags LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS, or disabled TLS verification.",
  },
  {
    id: "MCP007",
    severity: "MEDIUM",
    category: "supply-chain",
    title: "Untrusted temporary or relative executable path",
    summary: "Detects server binaries invoked from /tmp, /var/tmp, or relative paths.",
  },
  {
    id: "MCP008",
    severity: "LOW",
    category: "privilege",
    title: "Broad auto-approve or sandbox bypass flag",
    summary: "Flags wildcard autoApprove rules or --dangerously-skip-permissions / --allow-all flags.",
  },
];

const EPHEMERAL_RUNNERS = new Set(["npx", "uvx", "bunx", "pnpx"]);
const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"]);

const SECRET_VALUE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "OpenAI API key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { label: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { label: "GitHub token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/ },
  { label: "GitHub fine-grained PAT", regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { label: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: "Stripe live key", regex: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { label: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: "Private key PEM", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { label: "Bearer token", regex: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/i },
];

const SENSITIVE_KEY_REGEX = /(?:SECRET|TOKEN|API[_-]?KEY|PASSWORD|PASSWD|PRIVATE[_-]?KEY|AUTH|CREDENTIAL)/i;
const PLACEHOLDER_VALUE_REGEX = /^(?:\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|<[^>]+>|YOUR[_-]?.*|REPLACE[_-]?.*|CHANGEME|TODO|xxx+|placeholder|example)$/i;

const SENSITIVE_PATH_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "filesystem root (/)", regex: /^\/$/ },
  { label: "home directory (~ or $HOME)", regex: /^(?:~\/?|\$HOME\/?|\$\{HOME\}\/?|\/Users\/[^/]+\/?|\/home\/[^/]+\/?)$/ },
  { label: "SSH keys (~/.ssh)", regex: /(?:^|\/)\.ssh(?:\/|$)/ },
  { label: "AWS credentials (~/.aws)", regex: /(?:^|\/)\.aws(?:\/|$)/ },
  { label: "GnuPG keyring (~/.gnupg)", regex: /(?:^|\/)\.gnupg(?:\/|$)/ },
  { label: "Kubernetes config (~/.kube)", regex: /(?:^|\/)\.kube(?:\/|$)/ },
  { label: "system /etc directory", regex: /^\/etc(?:\/|$)/ },
];

const DANGEROUS_ENV_KEYS = new Set([
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "NODE_OPTIONS",
  "PYTHONPATH",
  "RUBYOPT",
]);

function baseCommand(cmd: string): string {
  const parts = cmd.split(/[\\/]/);
  return (parts[parts.length - 1] ?? cmd).toLowerCase();
}

function isPinnedPackage(spec: string): boolean {
  // Scoped: @scope/pkg@1.2.3 ; Unscoped: pkg@1.2.3 ; Python: pkg==1.2.3
  if (spec.startsWith("@")) {
    const secondAt = spec.indexOf("@", 1);
    if (secondAt === -1) return false;
    const version = spec.slice(secondAt + 1);
    return /^\d+\.\d+\.\d+/.test(version) && version !== "latest";
  }
  const atIdx = spec.indexOf("@");
  if (atIdx !== -1) {
    const version = spec.slice(atIdx + 1);
    return /^\d+\.\d+\.\d+/.test(version) && version !== "latest";
  }
  const eqIdx = spec.indexOf("==");
  if (eqIdx !== -1) {
    return /^\d+\.\d+/.test(spec.slice(eqIdx + 2));
  }
  return false;
}

function redactSecret(val: string): string {
  if (val.length <= 10) return "***";
  return `${val.slice(0, 6)}...${val.slice(-3)} (len=${val.length})`;
}

export function auditServerConfig(
  serverName: string,
  config: McpServerConfig,
  sourcePath: string
): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command ?? "";
  const cmdBase = baseCommand(cmd);
  const args = config.args ?? [];

  // MCP001: Unpinned ephemeral package runner
  if (EPHEMERAL_RUNNERS.has(cmdBase) || (cmdBase === "pnpm" && args[0] === "dlx")) {
    const pkgArg = args.find(
      (a) =>
        !a.startsWith("-") &&
        a !== "dlx" &&
        a !== "exec" &&
        !a.includes("=")
    );
    if (pkgArg && !isPinnedPackage(pkgArg)) {
      findings.push({
        ruleId: "MCP001",
        severity: "HIGH",
        category: "supply-chain",
        title: "Unpinned ephemeral package runner",
        message: `Server "${serverName}" launches "${pkgArg}" via "${cmdBase}" without an exact version pin. A compromised upstream release will execute automatically on next start.`,
        source: sourcePath,
        server: serverName,
        evidence: `${cmd} ${args.join(" ")}`.trim(),
        remediation: `Pin an exact immutable version (e.g., "${pkgArg}@1.2.3" or "${pkgArg}==1.2.3") and lock tool schemas with "mcp-audit pin".`,
      });
    }
  }

  // MCP002: Hardcoded secrets in env or headers
  const checkSecretMap = (map: Record<string, string> | undefined, loc: "env" | "headers"): void => {
    if (!map) return;
    for (const [key, value] of Object.entries(map)) {
      const trimmed = value.trim();
      if (!trimmed || PLACEHOLDER_VALUE_REGEX.test(trimmed)) continue;

      const matchedPattern = SECRET_VALUE_PATTERNS.find((p) => p.regex.test(trimmed));
      if (matchedPattern) {
        findings.push({
          ruleId: "MCP002",
          severity: "CRITICAL",
          category: "secrets",
          title: `Hardcoded ${matchedPattern.label} in ${loc}`,
          message: `Server "${serverName}" stores a literal ${matchedPattern.label} in ${loc}.${key}.`,
          source: sourcePath,
          server: serverName,
          evidence: `${loc}.${key} = ${redactSecret(trimmed)}`,
          remediation: `Remove the literal secret from the MCP config file and inject it from your OS keychain or a runtime environment reference.`,
        });
      } else if (SENSITIVE_KEY_REGEX.test(key) && trimmed.length >= 12) {
        findings.push({
          ruleId: "MCP002",
          severity: "CRITICAL",
          category: "secrets",
          title: `Hardcoded credential in ${loc}.${key}`,
          message: `Server "${serverName}" sets sensitive key ${loc}.${key} to a hardcoded literal value instead of an environment reference.`,
          source: sourcePath,
          server: serverName,
          evidence: `${loc}.${key} = ${redactSecret(trimmed)}`,
          remediation: `Replace the hardcoded value with an environment variable reference or secret manager lookup.`,
        });
      }
    }
  };
  checkSecretMap(config.env, "env");
  checkSecretMap(config.headers, "headers");

  // MCP003: Insecure remote transport
  if (config.url) {
    try {
      const parsed = new URL(config.url);
      const host = parsed.hostname.toLowerCase();
      const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "::1";
      if (parsed.protocol === "http:" && !isLoopback) {
        findings.push({
          ruleId: "MCP003",
          severity: "HIGH",
          category: "transport",
          title: "Unencrypted remote HTTP MCP endpoint",
          message: `Server "${serverName}" connects over plaintext HTTP to non-loopback host "${host}". Tool schemas and responses can be tampered with in transit.`,
          source: sourcePath,
          server: serverName,
          evidence: config.url,
          remediation: `Use HTTPS (TLS) for all non-loopback MCP servers.`,
        });
      }
      if (host === "0.0.0.0") {
        findings.push({
          ruleId: "MCP003",
          severity: "HIGH",
          category: "transport",
          title: "Wildcard 0.0.0.0 MCP endpoint",
          message: `Server "${serverName}" targets wildcard interface 0.0.0.0, risking unintended network exposure.`,
          source: sourcePath,
          server: serverName,
          evidence: config.url,
          remediation: `Bind local MCP servers strictly to 127.0.0.1 or localhost.`,
        });
      }
    } catch {
      findings.push({
        ruleId: "MCP003",
        severity: "MEDIUM",
        category: "transport",
        title: "Malformed MCP server URL",
        message: `Server "${serverName}" has an unparseable URL: "${config.url}".`,
        source: sourcePath,
        server: serverName,
        evidence: config.url,
        remediation: `Verify the remote MCP server URL syntax.`,
      });
    }
  }

  // MCP004: Shell wrapper / piped remote execution
  const joinedArgs = args.join(" ");
  if (
    SHELL_BINARIES.has(cmdBase) &&
    args.some((a) => a === "-c" || a === "/c" || a === "-Command" || a === "-lc")
  ) {
    findings.push({
      ruleId: "MCP004",
      severity: "HIGH",
      category: "privilege",
      title: "Shell wrapper command execution",
      message: `Server "${serverName}" executes through an interactive shell wrapper ("${cmdBase}"), expanding attack surface for command injection and unpinned remote scripts.`,
      source: sourcePath,
      server: serverName,
      evidence: `${cmd} ${joinedArgs}`.slice(0, 140),
      remediation: `Invoke the target executable directly in "command" with explicit "args" instead of wrapping in a shell.`,
    });
  } else if (/(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|zsh|python)/i.test(joinedArgs)) {
    findings.push({
      ruleId: "MCP004",
      severity: "HIGH",
      category: "privilege",
      title: "Piped remote script execution",
      message: `Server "${serverName}" downloads and pipes remote code directly into an interpreter.`,
      source: sourcePath,
      server: serverName,
      evidence: joinedArgs.slice(0, 140),
      remediation: `Install and verify a pinned local package instead of piping remote scripts.`,
    });
  }

  // MCP005: Over-privileged filesystem / credential directory mounts
  for (const arg of args) {
    const matched = SENSITIVE_PATH_PATTERNS.find((p) => p.regex.test(arg));
    if (matched) {
      findings.push({
        ruleId: "MCP005",
        severity: "HIGH",
        category: "privilege",
        title: `Over-privileged path scope: ${matched.label}`,
        message: `Server "${serverName}" receives broad or sensitive filesystem path "${arg}" (${matched.label}) in its arguments.`,
        source: sourcePath,
        server: serverName,
        evidence: `arg = "${arg}"`,
        remediation: `Scope filesystem MCP servers to a single dedicated project directory (least privilege).`,
      });
    }
  }

  // MCP006: Dangerous runtime env overrides
  if (config.env) {
    for (const [k, v] of Object.entries(config.env)) {
      if (DANGEROUS_ENV_KEYS.has(k)) {
        findings.push({
          ruleId: "MCP006",
          severity: "MEDIUM",
          category: "privilege",
          title: `Dangerous runtime loader override (${k})`,
          message: `Server "${serverName}" sets ${k}, which can inject arbitrary shared libraries or runtime flags into the server process.`,
          source: sourcePath,
          server: serverName,
          evidence: `env.${k} = "${v}"`,
          remediation: `Remove ${k} unless strictly required and audited.`,
        });
      }
      if (k === "NODE_TLS_REJECT_UNAUTHORIZED" && v.trim() === "0") {
        findings.push({
          ruleId: "MCP006",
          severity: "HIGH",
          category: "transport",
          title: "TLS certificate verification disabled",
          message: `Server "${serverName}" sets NODE_TLS_REJECT_UNAUTHORIZED=0, disabling HTTPS certificate validation.`,
          source: sourcePath,
          server: serverName,
          evidence: "env.NODE_TLS_REJECT_UNAUTHORIZED = 0",
          remediation: `Remove NODE_TLS_REJECT_UNAUTHORIZED=0 and configure a proper CA bundle if needed.`,
        });
      }
    }
  }

  // MCP007: Untrusted temp or relative executable path
  if (cmd && (/^(?:\/tmp\/|\/var\/tmp\/|\.\/|\.\.\/)/.test(cmd))) {
    findings.push({
      ruleId: "MCP007",
      severity: "MEDIUM",
      category: "supply-chain",
      title: "Untrusted temporary or relative server binary path",
      message: `Server "${serverName}" launches an executable from a temporary or relative path ("${cmd}").`,
      source: sourcePath,
      server: serverName,
      evidence: `command = "${cmd}"`,
      remediation: `Use an absolute path inside a trusted, read-only installation directory.`,
    });
  }

  // MCP008: Broad auto-approve or sandbox bypass
  const hasWildcardAutoApprove = config.autoApprove?.some((t) => t === "*" || t === "all");
  const hasBypassFlag = args.some((a) =>
    ["--allow-all", "--dangerously-skip-permissions", "--no-sandbox", "--yolo"].includes(a)
  );
  if (hasWildcardAutoApprove || hasBypassFlag) {
    findings.push({
      ruleId: "MCP008",
      severity: "LOW",
      category: "privilege",
      title: "Broad auto-approval or sandbox bypass configured",
      message: `Server "${serverName}" enables blanket tool auto-approval or disables sandbox protections.`,
      source: sourcePath,
      server: serverName,
      evidence: hasWildcardAutoApprove
        ? `autoApprove = ${JSON.stringify(config.autoApprove)}`
        : args.join(" "),
      remediation: `Approve only specific read-only tools explicitly and keep sandbox checks enabled.`,
    });
  }

  return findings;
}
