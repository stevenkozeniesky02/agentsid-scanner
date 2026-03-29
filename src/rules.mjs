/**
 * Security scanning rules engine.
 *
 * Each rule is a function that receives scan context and returns findings.
 * Rules are organized by category: auth, permissions, injection, validation,
 * secrets, output, transport, configuration.
 *
 * Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
 */

// ─── Tool Description Injection Patterns ───
// These patterns in tool descriptions can manipulate LLM behavior.

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)/i, name: "instruction_override", severity: "CRITICAL" },
  { pattern: /disregard\s+(previous|prior|above|all)/i, name: "instruction_override", severity: "CRITICAL" },
  { pattern: /you\s+are\s+now\s+a/i, name: "role_hijack", severity: "CRITICAL" },
  { pattern: /forget\s+(everything|all|previous)/i, name: "memory_wipe", severity: "CRITICAL" },
  { pattern: /instead\s+of\s+\w+,?\s*(call|use|execute|run)/i, name: "tool_redirect", severity: "HIGH" },
  { pattern: /also\s+(call|execute|run|invoke)\s+/i, name: "hidden_action", severity: "HIGH" },
  { pattern: /do\s+not\s+(tell|show|reveal|mention)\s+(the\s+)?user/i, name: "concealment", severity: "HIGH" },
  { pattern: /secretly|covertly|without\s+(the\s+)?user\s+knowing/i, name: "stealth_action", severity: "HIGH" },
  { pattern: /override|bypass|skip|ignore\s+(auth|security|permission|validation)/i, name: "security_bypass", severity: "CRITICAL" },
  { pattern: /base64|atob|btoa|eval\s*\(/i, name: "encoded_payload", severity: "MEDIUM" },
  { pattern: /\{%|<%|<\?|{{.*}}/i, name: "template_injection", severity: "MEDIUM" },
  { pattern: /\\u[0-9a-f]{4}|\\x[0-9a-f]{2}/i, name: "unicode_obfuscation", severity: "MEDIUM" },
];

// ─── Dangerous Tool Name Patterns ───
// Tools with these names are high-risk without permission controls.

const DANGEROUS_TOOL_PATTERNS = [
  { pattern: /^(delete|remove|drop|truncate|purge|destroy|wipe|erase)/i, risk: "destructive", severity: "HIGH" },
  { pattern: /(delete|remove|drop|truncate|purge|destroy|wipe|erase)$/i, risk: "destructive", severity: "HIGH" },
  { pattern: /^(execute|exec|run|eval|shell|cmd|command|bash|terminal)/i, risk: "execution", severity: "CRITICAL" },
  { pattern: /^(deploy|publish|release|push|ship)/i, risk: "deployment", severity: "HIGH" },
  { pattern: /^(admin|root|sudo|superuser|elevate)/i, risk: "privilege", severity: "CRITICAL" },
  { pattern: /(password|secret|key|token|credential|auth)/i, risk: "credential_access", severity: "HIGH" },
  { pattern: /^(send|email|message|notify|post|tweet|slack)/i, risk: "external_action", severity: "MEDIUM" },
  { pattern: /(payment|charge|bill|invoice|transfer|withdraw)/i, risk: "financial", severity: "CRITICAL" },
  { pattern: /^(create|insert|update|modify|set|write)/i, risk: "mutation", severity: "MEDIUM" },
  { pattern: /^(read|get|list|show|describe|fetch|query|search|find)/i, risk: "read_only", severity: "INFO" },
];

// ─── Input Validation Checks ───
// Schema patterns that indicate missing validation.

const SCHEMA_WEAKNESS_PATTERNS = [
  { check: (schema) => !schema || Object.keys(schema).length === 0, name: "no_schema", severity: "HIGH", desc: "Tool accepts arbitrary input with no schema validation" },
  { check: (schema) => schema?.type === "object" && (!schema.properties || Object.keys(schema.properties).length === 0), name: "empty_schema", severity: "MEDIUM", desc: "Schema defined but no properties specified" },
  { check: (schema) => schema?.type === "object" && !schema.required?.length, name: "no_required_fields", severity: "LOW", desc: "No required fields — all input is optional" },
  { check: (schema) => {
    const props = schema?.properties || {};
    return Object.values(props).some(p => p.type === "string" && !p.maxLength && !p.pattern && !p.enum);
  }, name: "unbounded_strings", severity: "MEDIUM", desc: "String parameters without length limits or pattern validation" },
];

// ─── Scan Rules ───

export function scanToolDescriptions(tools) {
  const findings = [];

  for (const tool of tools) {
    const desc = (tool.description || "").toLowerCase();
    const name = tool.name || "";

    // Check for injection patterns in description
    for (const rule of INJECTION_PATTERNS) {
      if (rule.pattern.test(tool.description || "")) {
        findings.push({
          category: "injection",
          severity: rule.severity,
          tool: name,
          rule: rule.name,
          detail: `Tool description contains potential prompt injection pattern: "${rule.name}"`,
          evidence: (tool.description || "").substring(0, 200),
        });
      }
    }

    // Check for excessively long descriptions (injection hiding)
    if ((tool.description || "").length > 1000) {
      findings.push({
        category: "injection",
        severity: "MEDIUM",
        tool: name,
        rule: "excessive_description_length",
        detail: `Tool description is ${(tool.description || "").length} chars — unusually long, may contain hidden instructions`,
      });
    }
  }

  return findings;
}

export function scanToolNames(tools) {
  const findings = [];
  const riskProfile = { read_only: 0, mutation: 0, destructive: 0, execution: 0, privilege: 0, financial: 0 };

  for (const tool of tools) {
    const name = tool.name || "";

    for (const rule of DANGEROUS_TOOL_PATTERNS) {
      if (rule.pattern.test(name)) {
        riskProfile[rule.risk] = (riskProfile[rule.risk] || 0) + 1;

        if (rule.severity !== "INFO") {
          findings.push({
            category: "permissions",
            severity: rule.severity,
            tool: name,
            rule: `dangerous_tool_${rule.risk}`,
            detail: `Tool "${name}" classified as ${rule.risk} — requires permission controls`,
          });
        }
      }
    }
  }

  return { findings, riskProfile };
}

export function scanInputSchemas(tools) {
  const findings = [];

  for (const tool of tools) {
    const schema = tool.inputSchema;
    const name = tool.name || "";

    for (const rule of SCHEMA_WEAKNESS_PATTERNS) {
      if (rule.check(schema)) {
        findings.push({
          category: "validation",
          severity: rule.severity,
          tool: name,
          rule: rule.name,
          detail: `${rule.desc} in tool "${name}"`,
        });
      }
    }
  }

  return findings;
}

export function scanAuthIndicators(tools, serverInfo) {
  const findings = [];

  // Check if server name/version suggests auth awareness
  const hasAuthTool = tools.some(t =>
    /auth|login|token|credential|session/i.test(t.name)
  );

  if (!hasAuthTool) {
    findings.push({
      category: "auth",
      severity: "HIGH",
      tool: "*",
      rule: "no_auth_tools",
      detail: "Server exposes no authentication-related tools — may accept unauthenticated connections",
    });
  }

  // Check tool count — more tools = higher attack surface
  if (tools.length > 20) {
    findings.push({
      category: "permissions",
      severity: "MEDIUM",
      tool: "*",
      rule: "large_tool_surface",
      detail: `Server exposes ${tools.length} tools — large attack surface without per-tool permission controls`,
    });
  }

  if (tools.length > 50) {
    findings.push({
      category: "permissions",
      severity: "HIGH",
      tool: "*",
      rule: "excessive_tool_surface",
      detail: `Server exposes ${tools.length} tools — excessive attack surface, strongly recommends per-agent tool scoping`,
    });
  }

  return findings;
}

export function scanOutputSafety(tools) {
  const findings = [];

  // Check for tools that might leak data
  for (const tool of tools) {
    const desc = (tool.description || "").toLowerCase();
    const name = tool.name || "";

    if (/secret|password|credential|key|token/i.test(desc) && /return|output|display|show|get/i.test(desc)) {
      findings.push({
        category: "secrets",
        severity: "HIGH",
        tool: name,
        rule: "potential_secret_exposure",
        detail: `Tool "${name}" may expose secrets in its output based on description`,
      });
    }

    if (/file|read|cat|content/i.test(name) && !/sanitiz|filter|redact/i.test(desc)) {
      findings.push({
        category: "output",
        severity: "LOW",
        tool: name,
        rule: "unfiltered_file_output",
        detail: `File reading tool "${name}" may output sensitive file contents without filtering`,
      });
    }
  }

  return findings;
}
