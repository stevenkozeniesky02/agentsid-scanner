/**
 * Mitigation layer — sits between raw finding generation and scoring.
 *
 * Each finding gets a confidence score: "high", "medium", "low".
 * Rules that fire on keyword-only matches get "low" confidence.
 * Rules corroborated by schema analysis or cross-tool context get "high".
 *
 * The grader uses confidence to weight deductions — a low-confidence
 * CRITICAL hurts less than a high-confidence CRITICAL.
 */

// ─── Schema Analysis ───────────────────────────────────────────

function schemaQuality(tool) {
  const schema = tool.inputSchema;
  if (!schema || Object.keys(schema).length === 0) return 0;

  let score = 0;
  const props = schema.properties || {};
  const propCount = Object.keys(props).length;

  if (propCount > 0) score += 1;
  if (schema.required?.length > 0) score += 1;

  const constrained = Object.values(props).filter(
    (p) => p.enum || p.maxLength || p.pattern || p.maximum || p.minimum
  ).length;
  if (constrained > 0) score += 1;
  if (propCount > 0 && constrained === propCount) score += 1;

  return score; // 0 = no schema, 4 = fully constrained
}

function hasConstrainedOutput(tool) {
  const schema = tool.inputSchema;
  if (!schema) return false;
  const props = schema.properties || {};
  return Object.values(props).some(
    (p) => p.enum || p.pattern || (p.type === "string" && p.maxLength)
  );
}

// ─── Tool Lookup Helpers ───────────────────────────────────────

function buildToolMap(tools) {
  const map = {};
  for (const tool of tools) {
    map[tool.name || ""] = tool;
  }
  return map;
}

function toolIsReadOnly(tool) {
  const name = (tool.name || "").toLowerCase();
  return /^(read|get|list|show|describe|fetch|query|search|find|count|check|verify|status|info|ping|health|version)/.test(name);
}

// ─── Auth Context ──────────────────────────────────────────────

function detectTransportAuth(tools, serverInfo) {
  const allText = tools
    .map((t) => `${t.name || ""} ${t.description || ""}`)
    .join(" ")
    .toLowerCase();

  const serverText = `${serverInfo?.name || ""} ${serverInfo?.version || ""}`.toLowerCase();

  // Check if any tool schemas require auth-related parameters
  const hasAuthParam = tools.some((t) => {
    const props = t.inputSchema?.properties || {};
    return Object.keys(props).some((k) =>
      /token|api_key|apikey|authorization|auth|bearer|credential|secret/i.test(k)
    );
  });

  // Check if server description mentions auth
  const mentionsAuth = /oauth|jwt|bearer|api.?key|auth|authenticated|credential|session/i.test(
    allText + " " + serverText
  );

  return hasAuthParam || mentionsAuth;
}

// ─── Description Intent ────────────────────────────────────────

function isExpansiveDescription(desc) {
  return /always\s+(use|call|run|invoke|execute)|before\s+any\s+other|call\s+this\s+first|must\s+be\s+called|required\s+before/i.test(desc);
}

// ─── Mitigation Rules ──────────────────────────────────────────

function mitigateFinding(finding, toolMap, tools, serverInfo, authContext) {
  const tool = toolMap[finding.tool] || null;
  const sq = tool ? schemaQuality(tool) : 0;
  const readOnly = tool ? toolIsReadOnly(tool) : false;

  // Start with medium confidence — keyword match is the baseline
  let confidence = "medium";
  let adjustedSeverity = finding.severity;

  switch (finding.rule) {
    // ── Mutation tools (create/update/write): normal CRUD, not dangerous ──
    case "dangerous_tool_mutation":
    case "dangerous_tool_external_action": {
      if (sq >= 2) {
        // Has properties + required fields — scoped mutation
        adjustedSeverity = "INFO";
        confidence = "low";
      } else if (sq >= 1) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else {
        // No schema at all — unconstrained mutation is a real risk
        confidence = "medium";
      }
      break;
    }

    // ── Destructive tools (delete/drop/purge): real risk, but schema matters ──
    case "dangerous_tool_destructive":
    case "dangerous_tool_deployment":
    case "dangerous_tool_credential_access": {
      if (sq >= 3) {
        adjustedSeverity = downgrade(adjustedSeverity);
        confidence = "low";
      } else if (sq >= 1) {
        confidence = "medium";
      } else {
        confidence = "high";
      }
      break;
    }

    // ── Execution/privilege/financial: always dangerous, schema only adjusts confidence ──
    case "dangerous_tool_execution":
    case "dangerous_tool_privilege":
    case "dangerous_tool_financial": {
      if (sq >= 3) {
        confidence = "medium";
      } else {
        confidence = "high";
      }
      break;
    }

    // ── No auth tools: suppress if transport-level auth detected ──
    case "no_auth_tools": {
      if (authContext) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else {
        confidence = "high";
      }
      break;
    }

    // ── Tool surface area: reduce if tools are mostly read-only ──
    case "large_tool_surface":
    case "excessive_tool_surface": {
      const readOnlyCount = tools.filter(toolIsReadOnly).length;
      const readOnlyRatio = readOnlyCount / tools.length;
      if (readOnlyRatio > 0.7) {
        adjustedSeverity = downgrade(adjustedSeverity);
        confidence = "low";
      } else {
        confidence = "medium";
      }
      break;
    }

    // ── Secret exposure: check if description actually returns secrets ──
    case "potential_secret_exposure": {
      const desc = (tool?.description || "").toLowerCase();
      // If description talks about expiry, status, validation — not the secret itself
      if (/expir|status|valid|check|verify|revoke|rotate|refresh/i.test(desc)) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else {
        confidence = "medium";
      }
      break;
    }

    // ── Vague descriptions: only flag if combined with sensitive resources ──
    case "vague_description_over_privilege": {
      const desc = (tool?.description || "").toLowerCase();
      if (readOnly) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else if (isExpansiveDescription(desc)) {
        confidence = "high";
      } else {
        confidence = "low";
      }
      break;
    }

    // ── Ambiguous tool name: lower if schema provides clarity ──
    case "ambiguous_tool_name": {
      if (sq >= 2) {
        adjustedSeverity = downgrade(adjustedSeverity);
        confidence = "low";
      } else {
        confidence = "medium";
      }
      break;
    }

    // ── No description: lower if tool name is self-explanatory ──
    case "no_description": {
      if (readOnly) {
        adjustedSeverity = "MEDIUM";
        confidence = "low";
      } else if (sq >= 2) {
        adjustedSeverity = "MEDIUM";
        confidence = "low";
      } else {
        confidence = "high";
      }
      break;
    }

    // ── Implicit authority escalation: check if schema constrains the danger ──
    case "implicit_authority_escalation": {
      if (sq >= 3) {
        adjustedSeverity = "MEDIUM";
        confidence = "low";
      } else if (sq >= 1) {
        adjustedSeverity = "HIGH";
        confidence = "medium";
      } else {
        confidence = "high";
      }
      break;
    }

    // ── Schema weaknesses: lower for read-only tools ──
    case "no_schema": {
      if (readOnly) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else {
        confidence = "high";
      }
      break;
    }

    case "unbounded_strings": {
      if (readOnly) {
        adjustedSeverity = "LOW";
        confidence = "low";
      } else {
        confidence = "medium";
      }
      break;
    }

    // ── Toxic data flow: check if sender tool has constrained outputs ──
    case "toxic_data_flow": {
      const evidence = finding.evidence || "";
      // Extract network_sender tools from evidence
      const senderMatch = evidence.match(/network_sender:\s*\[([^\]]+)\]/);
      if (senderMatch) {
        const senderNames = senderMatch[1].split(",").map((s) => s.trim());
        const allSendersConstrained = senderNames.every((name) => {
          const senderTool = toolMap[name];
          return senderTool && hasConstrainedOutput(senderTool);
        });
        if (allSendersConstrained) {
          adjustedSeverity = downgrade(adjustedSeverity);
          confidence = "low";
        } else {
          confidence = "high";
        }
      } else {
        confidence = "high";
      }
      break;
    }

    // ── Injection patterns: always high confidence (real signal) ──
    case "instruction_override":
    case "role_hijack":
    case "memory_wipe":
    case "tool_redirect":
    case "hidden_action":
    case "concealment":
    case "stealth_action":
    case "security_bypass":
    case "hidden_characters": {
      confidence = "high";
      break;
    }

    // ── Everything else: medium confidence ──
    default: {
      confidence = "medium";
      break;
    }
  }

  return {
    ...finding,
    severity: adjustedSeverity,
    originalSeverity: finding.severity !== adjustedSeverity ? finding.severity : undefined,
    confidence,
  };
}

// ─── Severity Helpers ──────────────────────────────────────────

const SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function downgrade(severity) {
  const idx = SEVERITY_ORDER.indexOf(severity);
  return idx > 0 ? SEVERITY_ORDER[idx - 1] : severity;
}

// ─── Public API ────────────────────────────────────────────────

/**
 * Apply mitigations to raw findings.
 * Returns findings with adjusted severity and confidence scores.
 */
export function applyMitigations(findings, tools, serverInfo) {
  const toolMap = buildToolMap(tools);
  const authContext = detectTransportAuth(tools, serverInfo);

  return findings.map((f) =>
    mitigateFinding(f, toolMap, tools, serverInfo, authContext)
  );
}
