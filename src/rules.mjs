/**
 * Security scanning rules engine.
 *
 * Each rule is a function that receives scan context and returns findings.
 * Rules are organized by category: auth, permissions, injection, validation,
 * secrets, output, transport, configuration.
 *
 * Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
 */

// ─── Deobfuscation ───
// Strip Unicode characters commonly used to hide payloads in tool descriptions.
// Returns sanitized text. Caller should compare to original to detect obfuscation.

function sanitizeDescription(text) {
  if (!text) return text;
  return text
    // Unicode tag block U+E0000-U+E007F — invisible characters used to encode hidden text
    .replace(/[\u{E0000}-\u{E007F}]/gu, "")
    // Zero-width characters
    .replace(/[\u200B\u200C\u200D\uFEFF]/g, "")
    // Variation selectors U+FE00-U+FE0F
    .replace(/[\uFE00-\uFE0F]/g, "")
    // BiDi control characters — used to reverse text direction to hide content
    .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, "");
}

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
    const raw = tool.description || "";
    const sanitized = sanitizeDescription(raw);
    const name = tool.name || "";

    // Detect hidden characters — sanitized text differs from raw
    if (sanitized !== raw) {
      const hiddenCount = [...raw].length - [...sanitized].length;
      findings.push({
        category: "injection",
        severity: "CRITICAL",
        tool: name,
        rule: "hidden_characters",
        detail: `Tool description contains ${hiddenCount} hidden Unicode character(s) — payload may be concealed using tag block, zero-width, or BiDi characters`,
        evidence: `raw length: ${raw.length} → sanitized length: ${sanitized.length}`,
      });
    }

    // Run injection patterns against sanitized text (reveals hidden payloads)
    for (const rule of INJECTION_PATTERNS) {
      if (rule.pattern.test(sanitized)) {
        findings.push({
          category: "injection",
          severity: rule.severity,
          tool: name,
          rule: rule.name,
          detail: `Tool description contains potential prompt injection pattern: "${rule.name}"`,
          evidence: sanitized.substring(0, 200),
        });
      }
    }

    // Check for excessively long descriptions (injection hiding)
    if (sanitized.length > 1000) {
      findings.push({
        category: "injection",
        severity: "MEDIUM",
        tool: name,
        rule: "excessive_description_length",
        detail: `Tool description is ${sanitized.length} chars — unusually long, may contain hidden instructions`,
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
      const match = rule.pattern.exec(name);
      if (match) {
        riskProfile[rule.risk] = (riskProfile[rule.risk] || 0) + 1;

        if (rule.severity !== "INFO") {
          findings.push({
            category: "permissions",
            severity: rule.severity,
            tool: name,
            rule: `dangerous_tool_${rule.risk}`,
            detail: `Tool "${name}" classified as ${rule.risk} — requires permission controls`,
            evidence: match[0],
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

// ═══════════════════════════════════════════════════════════════
// HALLUCINATION-BASED VULNERABILITY SCANNING
//
// These detect cases where vague, ambiguous, or misleading tool
// definitions cause LLMs to over-privilege, misroute, or make
// unpredictable tool choices.
//
// Nobody else scans for these.
// ═══════════════════════════════════════════════════════════════

const VAGUE_ACTION_WORDS = [
  "manage", "handle", "process", "work with", "deal with",
  "interact", "operate on", "perform", "do", "run",
  "access", "use", "control", "modify", "change",
  "update", "affect", "manipulate", "transform",
];

const SPECIFIC_ACTION_WORDS = [
  "read", "write", "delete", "create", "list", "get", "set",
  "search", "find", "count", "validate", "check", "verify",
  "send", "receive", "upload", "download", "export", "import",
];

const SENSITIVE_RESOURCES = [
  "file", "database", "user", "account", "payment", "credential",
  "config", "setting", "permission", "role", "secret", "key",
  "server", "cluster", "deployment", "container", "network",
  "email", "message", "notification", "webhook",
];

export function scanHallucinationRisks(tools) {
  const findings = [];

  for (const tool of tools) {
    const desc = (tool.description || "");
    const descLower = desc.toLowerCase();
    const name = (tool.name || "");

    // 1. Vague description causing over-privileging
    const vagueMatches = VAGUE_ACTION_WORDS.filter(w => descLower.includes(w));
    const specificMatches = SPECIFIC_ACTION_WORDS.filter(w => descLower.includes(w));
    const sensitiveMatches = SENSITIVE_RESOURCES.filter(w => descLower.includes(w));

    if (vagueMatches.length > 0 && specificMatches.length === 0) {
      findings.push({
        category: "hallucination",
        severity: sensitiveMatches.length > 0 ? "HIGH" : "MEDIUM",
        tool: name,
        rule: "vague_description_over_privilege",
        detail: `Tool "${name}" uses vague action words (${vagueMatches.join(", ")}) without specific operations. LLMs will interpret this as the broadest possible action${sensitiveMatches.length > 0 ? ` on sensitive resources (${sensitiveMatches.join(", ")})` : ""}.`,
      });
    }

    // 2. Ambiguous tool name
    const ambiguousVerbs = ["manage", "handle", "process", "admin", "control", "maintain"];
    const nameVerb = name.split(/[_\-\.]/)[0]?.toLowerCase();
    if (ambiguousVerbs.includes(nameVerb)) {
      findings.push({
        category: "hallucination",
        severity: "HIGH",
        tool: name,
        rule: "ambiguous_tool_name",
        detail: `Tool name "${name}" is ambiguous — "${nameVerb}" could mean read, create, update, or delete. LLM may choose the most destructive interpretation.`,
      });
    }

    // 3. Missing scope boundaries
    if (sensitiveMatches.length > 0 && !/only|restrict|limit|within|specific|allowed|scoped|bounded/i.test(desc)) {
      if (!/must|should|cannot|must not|only if|requires/i.test(desc)) {
        findings.push({
          category: "hallucination",
          severity: "MEDIUM",
          tool: name,
          rule: "missing_scope_boundary",
          detail: `Tool "${name}" references ${sensitiveMatches.join(", ")} without specifying scope boundaries. LLM will attempt to access the broadest possible scope.`,
        });
      }
    }

    // 4. Description too short — LLM fills in the gaps
    if (desc.length > 0 && desc.length < 20) {
      findings.push({
        category: "hallucination",
        severity: "MEDIUM",
        tool: name,
        rule: "description_too_short",
        detail: `Tool "${name}" description is only ${desc.length} chars. LLM will hallucinate capabilities based on the name alone.`,
      });
    }

    // 5. No description at all
    if (!desc || desc.trim().length === 0) {
      findings.push({
        category: "hallucination",
        severity: "HIGH",
        tool: name,
        rule: "no_description",
        detail: `Tool "${name}" has no description. LLM will infer behavior entirely from the name — unpredictable tool usage.`,
      });
    }

    // 6. Implicit authority escalation
    const innocuousWords = ["helper", "utility", "tool", "assistant", "basic", "simple", "general"];
    const dangerousNameParts = ["admin", "root", "sudo", "deploy", "delete", "drop", "exec", "shell", "kill"];
    const descInnocuous = innocuousWords.some(w => descLower.includes(w));
    const nameDangerous = dangerousNameParts.some(w => name.toLowerCase().includes(w));

    if (descInnocuous && nameDangerous) {
      findings.push({
        category: "hallucination",
        severity: "CRITICAL",
        tool: name,
        rule: "implicit_authority_escalation",
        detail: `Tool "${name}" has dangerous capabilities but is described as a "${innocuousWords.find(w => descLower.includes(w))}". LLM will underestimate the risk and use it without caution.`,
      });
    }
  }

  // 7. Conflicting/overlapping tool descriptions
  for (let i = 0; i < tools.length; i++) {
    for (let j = i + 1; j < tools.length; j++) {
      const descA = (tools[i].description || "").toLowerCase();
      const descB = (tools[j].description || "").toLowerCase();
      if (!descA || !descB) continue;

      const wordsA = new Set(descA.split(/\s+/).filter(w => w.length > 4));
      const wordsB = new Set(descB.split(/\s+/).filter(w => w.length > 4));
      const overlap = [...wordsA].filter(w => wordsB.has(w));
      const overlapRatio = overlap.length / Math.min(wordsA.size, wordsB.size);

      if (overlapRatio > 0.6 && overlap.length >= 5) {
        findings.push({
          category: "hallucination",
          severity: "MEDIUM",
          tool: `${tools[i].name} + ${tools[j].name}`,
          rule: "conflicting_tool_descriptions",
          detail: `Tools "${tools[i].name}" and "${tools[j].name}" have ${Math.round(overlapRatio * 100)}% description overlap. LLM may choose between them unpredictably.`,
        });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════
// TOXIC DATA FLOW DETECTION
//
// Identifies dangerous capability combinations across tools on a
// single server. A server with both an external reader and a
// network sender creates an exfiltration path even if no single
// tool is malicious on its own.
// ═══════════════════════════════════════════════════════════════

function classifyToolCapabilities(tool) {
  const name = (tool.name || "").toLowerCase();
  const desc = (tool.description || "").toLowerCase();
  const text = `${name} ${desc}`;
  const caps = new Set();

  if (/\b(email|inbox|gmail|outlook|slack|discord|teams|github|gitlab|jira|linear|notion|asana|calendar|feed|rss|sms|whatsapp|telegram|message|notification)\b/.test(text))
    caps.add("external_reader");

  if (/\b(secret|password|credential|api.?key|private.?key|keychain|vault|\.env|aws.?credential|ssh.?key|access.?token)\b/.test(text))
    caps.add("credential_reader");

  if (/^(write|save|create|append|overwrite|put)/.test(name) || /_(write|save|put)$/.test(name) || /write.{0,20}(file|disk|path)/.test(text))
    caps.add("file_writer");

  if (/^(read|get|fetch|download|export|load)/.test(name) && /\b(file|document|content|data|database)\b/.test(text))
    caps.add("data_reader");

  if (/\b(send.?email|send.?message|send.?slack|post.{0,10}(to|request)|upload|submit|forward|http.?request|make.?request|webhook)\b/.test(text) || /^(send|email|post|notify|alert|push|transmit)\b/.test(name))
    caps.add("network_sender");

  if (/\b(execute|exec|shell|bash|terminal|run.?command|eval|subprocess|spawn)\b/.test(text) || /^(exec|shell|bash|run|terminal|command)\b/.test(name))
    caps.add("code_executor");

  return caps;
}

const TOXIC_COMBINATIONS = [
  {
    a: "external_reader", b: "network_sender", severity: "CRITICAL",
    desc: "Server can read external sources (email/Slack/GitHub) and send to external destinations — data relay/exfiltration path",
  },
  {
    a: "credential_reader", b: "network_sender", severity: "CRITICAL",
    desc: "Server can access credentials and send data externally — credential exfiltration path",
  },
  {
    a: "external_reader", b: "code_executor", severity: "CRITICAL",
    desc: "Server can read external content and execute code — prompt injection to RCE path",
  },
  {
    a: "data_reader", b: "network_sender", severity: "HIGH",
    desc: "Server can read local files and send data externally — local data exfiltration path",
  },
  {
    a: "external_reader", b: "file_writer", severity: "HIGH",
    desc: "Server can read external content and write to local filesystem — external content staging path",
  },
  {
    a: "credential_reader", b: "file_writer", severity: "HIGH",
    desc: "Server can access credentials and write to local filesystem — credential staging path",
  },
];

export function scanToxicDataFlows(tools) {
  const findings = [];

  // Map each capability to the tools that have it
  const capToTools = {};
  for (const tool of tools) {
    for (const cap of classifyToolCapabilities(tool)) {
      if (!capToTools[cap]) capToTools[cap] = [];
      capToTools[cap].push(tool.name);
    }
  }

  for (const combo of TOXIC_COMBINATIONS) {
    if (capToTools[combo.a] && capToTools[combo.b]) {
      findings.push({
        category: "data-flow",
        severity: combo.severity,
        tool: "*",
        rule: "toxic_data_flow",
        detail: combo.desc,
        evidence: `${combo.a}: [${capToTools[combo.a].join(", ")}] + ${combo.b}: [${capToTools[combo.b].join(", ")}]`,
      });
    }
  }

  return findings;
}
