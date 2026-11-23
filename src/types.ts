export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type FindingCategory =
  | "supply-chain"
  | "secrets"
  | "transport"
  | "privilege"
  | "tool-poisoning"
  | "steganography"
  | "exfiltration"
  | "shadowing"
  | "schema"
  | "rug-pull";

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  message: string;
  source: string;
  server?: string;
  tool?: string;
  evidence?: string;
  remediation: string;
}

export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  transport?: string;
  autoApprove?: string[];
  disabled?: boolean;
  tools?: McpToolDefinition[];
}

export interface McpJsonSchema {
  type?: string | string[];
  description?: string;
  properties?: Record<string, McpJsonSchema>;
  required?: string[];
  additionalProperties?: boolean | McpJsonSchema;
  enum?: unknown[];
  pattern?: string;
  maxLength?: number;
  items?: McpJsonSchema;
  [key: string]: unknown;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: McpJsonSchema;
  annotations?: Record<string, unknown>;
}

export interface ParsedMcpSource {
  sourcePath: string;
  clientHint: string;
  servers: Record<string, McpServerConfig>;
  standaloneTools: Array<{ server: string; tools: McpToolDefinition[] }>;
}

export interface LockfileToolPin {
  sha256: string;
  descriptionLength: number;
}

export interface LockfileServerPin {
  configSha256: string;
  command?: string;
  args?: string[];
  url?: string;
  envKeys: string[];
  tools: Record<string, LockfileToolPin>;
}

export interface Lockfile {
  schemaVersion: "1.0";
  generatedAt: string;
  toolVersion: string;
  servers: Record<string, LockfileServerPin>;
}

export interface AuditSummary {
  filesScanned: number;
  serversScanned: number;
  toolsScanned: number;
  counts: Record<Severity, number>;
  riskScore: number;
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface AuditReport {
  tool: "mcp-audit";
  version: string;
  scannedAt: string;
  summary: AuditSummary;
  findings: Finding[];
}

export interface RuleMetadata {
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  summary: string;
}

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 15,
  MEDIUM: 7,
  LOW: 2,
  INFO: 0,
};
