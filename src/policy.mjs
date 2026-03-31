/**
 * MAP policy generation and finding description enrichment.
 *
 * Extracted from the Hall of MCPs pipeline so the CLI can produce
 * a ready-to-deploy agentsid.json in the same scan command.
 */

export function enrichDescription(rule, tool, detail) {
  const t = tool && tool !== "*" ? `\`${tool}\`` : "server";
  switch (rule) {
    case "dangerous_tool_destructive":
      return `${t} can permanently delete data — no guardrails, no confirmation required`;
    case "dangerous_tool_execution":
      return `${t} executes arbitrary code with no scope restriction or allowlist`;
    case "dangerous_tool_deployment":
      return `${t} can publish or deploy to production — any agent can trigger a release`;
    case "dangerous_tool_credential_access":
      return `${t} accesses credentials with no scope or audience restriction`;
    case "dangerous_tool_mutation":
      return `${t} mutates persistent state with no constraints — side effects are unrestricted`;
    case "dangerous_tool_external_action":
      return `${t} sends external requests with no domain or rate restriction`;
    case "dangerous_tool_financial":
      return `${t} can trigger financial operations — no spend limit or approval gate`;
    case "missing_scope_boundary":
      return `${t} references files or resources without scope limits — agent targets broadest possible path`;
    case "empty_schema":
      return `${t} schema has no properties — input is completely unconstrained, any argument accepted`;
    case "no_required_fields":
      return `${t} makes all parameters optional — can be invoked with zero arguments`;
    case "no_description":
      return `${t} has no description — LLM infers behavior from the name alone, unpredictable invocation`;
    case "description_too_short":
      return `${t} description is too short — LLM hallucinates capabilities from the name`;
    case "vague_description_over_privilege":
      return `${t} uses vague action words — LLM interprets scope as the broadest possible action`;
    case "no_auth_tools":
      return `Server exposes no auth mechanism — accepts connections from any unauthenticated agent`;
    case "large_tool_surface":
    case "excessive_tool_surface":
      return detail;
    case "conflicting_tool_descriptions":
      return detail;
    case "unbounded_strings":
      return `${t} accepts string parameters with no length limit or pattern validation`;
    case "unfiltered_file_output":
      return `${t} may return raw file contents including secrets, tokens, or credentials`;
    case "potential_secret_exposure":
      return `${t} response may leak secrets or API keys based on tool description`;
    case "encoded_payload":
      return `${t} description contains a potential prompt injection payload`;
    case "security_bypass":
      return `${t} description instructs the LLM to bypass security controls`;
    case "excessive_description_length":
      return `${t} has an unusually long description — may contain hidden instructions for the LLM`;
    default:
      return detail;
  }
}

export function buildMapPolicy(findings) {
  const rules = [];
  const seen = new Set();

  for (const f of findings) {
    const tool = f.tool && f.tool !== "*" ? f.tool : null;
    const key = `${f.rule}:${tool ?? "*"}`;
    if (seen.has(key)) continue;
    seen.add(key);

    switch (f.rule) {
      case "dangerous_tool_destructive":
        if (tool) rules.push({ tool, action: "deny" });
        break;
      case "dangerous_tool_execution":
        if (tool) rules.push({ tool, action: "allow", where: { callerTag: ["ci", "dev"] } });
        break;
      case "dangerous_tool_deployment":
        if (tool) rules.push({ tool, action: "allow", where: { callerTag: ["release-bot"] } });
        break;
      case "dangerous_tool_credential_access":
        if (tool) rules.push({ tool, action: "allow", where: { callerTag: ["auth-agent"] } });
        break;
      case "dangerous_tool_mutation":
        if (tool) rules.push({ tool, action: "allow", where: { callerTag: ["write-agent"] } });
        break;
      case "dangerous_tool_external_action":
        if (tool) rules.push({ tool, action: "allow", where: { allowedDomains: ["yourdomain.com"] } });
        break;
      case "dangerous_tool_financial":
        if (tool) rules.push({ tool, action: "allow", where: { budget: { maxUsd: 10 } } });
        break;
      case "missing_scope_boundary":
        if (tool) rules.push({ tool, action: "allow", where: { pathScope: "{{project_root}}" } });
        break;
      case "unbounded_strings":
        if (tool) rules.push({ tool, action: "allow", where: { maxLength: { query: 500 } } });
        break;
    }
  }

  rules.push({ tool: "*", action: "allow" });

  return { version: "1.0", rules };
}
