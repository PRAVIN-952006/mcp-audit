import * as fs from "node:fs";
import * as path from "node:path";
import { getDefaultDiscoveryCandidates, loadMcpFile, parseMcpJsonContent } from "./discover.ts";
import { buildLockfile, RUGPULL_RULES, verifyAgainstLockfile } from "./lockfile.ts";
import { probeStdioServer, type ProbeResult } from "./probe.ts";
import { formatJsonReport, formatSarifReport, formatTextReport } from "./reporters.ts";
import { auditServerConfig, CONFIG_RULES } from "./rules/config-rules.ts";
import { auditToolsAcrossServers, TOOL_RULES, type ToolAuditInput } from "./rules/tool-rules.ts";
import {
  SEVERITY_RANK,
  SEVERITY_WEIGHT,
  type AuditReport,
  type AuditSummary,
  type Finding,
  type Lockfile,
  type ParsedMcpSource,
  type RuleMetadata,
  type Severity,
} from "./types.ts";

export const TOOL_VERSION = "0.2.0";

export const ALL_RULES: RuleMetadata[] = [...CONFIG_RULES, ...TOOL_RULES, ...RUGPULL_RULES];

export {
  buildLockfile,
  formatJsonReport,
  formatSarifReport,
  formatTextReport,
  getDefaultDiscoveryCandidates,
  loadMcpFile,
  parseMcpJsonContent,
  probeStdioServer,
  verifyAgainstLockfile,
};
export type { ProbeResult };
export type * from "./types.ts";

function computeGrade(score: number): AuditSummary["grade"] {
  if (score === 0) return "A";
  if (score <= 15) return "B";
  if (score <= 35) return "C";
  if (score <= 65) return "D";
  return "F";
}

export async function probeSourcesLive(
  sources: ParsedMcpSource[],
  timeoutMs = 5000
): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  for (const src of sources) {
    for (const [serverName, cfg] of Object.entries(src.servers)) {
      if (cfg.disabled || !cfg.command) continue;
      const res = await probeStdioServer(serverName, cfg, timeoutMs);
      results.push(res);
      if (res.tools.length > 0) {
        cfg.tools = res.tools;
      }
    }
  }
  return results;
}

export function auditParsedSources(
  sources: ParsedMcpSource[],
  options?: { lockfile?: Lockfile; lockfilePath?: string }
): AuditReport {
  const findings: Finding[] = [];
  const toolInputs: ToolAuditInput[] = [];
  let serversScanned = 0;
  let toolsScanned = 0;

  for (const src of sources) {
    for (const [serverName, cfg] of Object.entries(src.servers)) {
      if (cfg.disabled) continue;
      serversScanned++;
      findings.push(...auditServerConfig(serverName, cfg, src.sourcePath));
      if (cfg.tools && cfg.tools.length > 0) {
        toolsScanned += cfg.tools.length;
        toolInputs.push({ server: serverName, sourcePath: src.sourcePath, tools: cfg.tools });
      }
    }
    for (const group of src.standaloneTools) {
      toolsScanned += group.tools.length;
      toolInputs.push({ server: group.server, sourcePath: src.sourcePath, tools: group.tools });
    }
  }

  findings.push(...auditToolsAcrossServers(toolInputs));

  if (options?.lockfile) {
    findings.push(
      ...verifyAgainstLockfile(sources, options.lockfile, options.lockfilePath ?? "mcp-audit.lock.json")
    );
  }

  findings.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.ruleId.localeCompare(b.ruleId);
  });

  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  let rawScore = 0;
  for (const f of findings) {
    counts[f.severity]++;
    rawScore += SEVERITY_WEIGHT[f.severity];
  }
  const riskScore = Math.min(100, rawScore);

  return {
    tool: "mcp-audit",
    version: TOOL_VERSION,
    scannedAt: new Date().toISOString(),
    summary: {
      filesScanned: sources.length,
      serversScanned,
      toolsScanned,
      counts,
      riskScore,
      grade: computeGrade(riskScore),
    },
    findings,
  };
}

export function loadSourcesFromPaths(targetPaths: string[]): ParsedMcpSource[] {
  const sources: ParsedMcpSource[] = [];
  if (targetPaths.length === 0) {
    for (const cand of getDefaultDiscoveryCandidates()) {
      try {
        sources.push(loadMcpFile(cand.filePath, cand.clientHint));
      } catch {
        // Ignore unreadable or non-JSON candidate files during auto-discovery
      }
    }
    return sources;
  }

  for (const p of targetPaths) {
    const resolved = path.resolve(p);
    const stat = fs.statSync(resolved);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(resolved)) {
        if (entry.endsWith(".json")) {
          sources.push(loadMcpFile(path.join(resolved, entry)));
        }
      }
    } else {
      sources.push(loadMcpFile(resolved));
    }
  }
  return sources;
}

export function shouldFailBuild(report: AuditReport, failOn?: Severity): boolean {
  if (!failOn) return false;
  const threshold = SEVERITY_RANK[failOn];
  return report.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
}
