/**
 * Reads all scan reports from /reports and generates
 * hall-of-mcps-data.ts for the website.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, "../reports");
const OUT_FILE = path.join(
  __dirname,
  "../../web/src/pages/hall-of-mcps-data.ts"
);

const NPM_SLUG_MAP = {
  "modelcontextprotocol-server-github": "@modelcontextprotocol/server-github",
  "modelcontextprotocol-server-filesystem": "@modelcontextprotocol/server-filesystem",
  "modelcontextprotocol-server-puppeteer": "@modelcontextprotocol/server-puppeteer",
  "modelcontextprotocol-server-memory": "@modelcontextprotocol/server-memory",
  "modelcontextprotocol-server-everything": "@modelcontextprotocol/server-everything",
  "modelcontextprotocol-server-postgres": "@modelcontextprotocol/server-postgres",
  "modelcontextprotocol-server-fetch": "@modelcontextprotocol/server-fetch",
  "modelcontextprotocol-server-brave-search": "@modelcontextprotocol/server-brave-search",
  "modelcontextprotocol-server-sequential-thinking": "@modelcontextprotocol/server-sequential-thinking",
  "playwright-mcp": "@playwright/mcp",
  "mcp-server-slack": "@modelcontextprotocol/server-slack",
  "notionhq-notion-mcp-server": "@notionhq/notion-mcp-server",
  "heroku-mcp-server": "@heroku/mcp-server",
  "railway-mcp-server": "railway-mcp-server",
  "chrome-devtools-mcp": "chrome-devtools-mcp",
  "european-parliament-mcp-server": "european-parliament-mcp-server",
  "azure-mcp": "@azure/mcp",
  "composio-mcp": "composio-mcp",
  "supabase-mcp-server-supabase": "@supabase/mcp-server-supabase",
  "sentry-mcp-server": "@sentry/mcp-server",
  "cloudflare-mcp-server": "@cloudflare/mcp-server-cloudflare",
  "hubspot-mcp-server": "@hubspot/mcp-server",
  "mcp-server-kubernetes": "mcp-server-kubernetes",
  "mcp-server-docker": "mcp-server-docker",
  "mcp-server-google-calendar": "mcp-server-google-calendar",
  "mcp-server-jira-cloud": "mcp-server-jira-cloud",
  "mcp-server-sqlite-npx": "@modelcontextprotocol/server-sqlite",
  "agentdeskai-browser-tools-mcp": "@agentdesk/browser-tools-mcp",
  "aashari-mcp-server-atlassian-jira": "@aashari/mcp-server-atlassian-jira",
  "aashari-mcp-server-atlassian-confluence": "@aashari/mcp-server-atlassian-confluence",
  "aashari-mcp-server-aws-sso": "@aashari/mcp-server-aws-sso",
  "exa-mcp-server": "exa-mcp-server",
  "tavily-mcp": "@tavily/mcp",
  "desktop-commander": "desktop-commander",
  "wonderwhy-er-desktop-commander": "@wonderwhy-er/desktop-commander",
  "aiondadotcom-mcp-ssh": "@aionda/mcp-ssh",
  "dbhub": "dbhub",
  "e2b-mcp-server": "@e2b/mcp-server",
  "figma-mcp": "figma-mcp",
  "mapbox-mcp-server": "@mapbox/mcp-server",
  "upstash-context7-mcp": "@upstash/context7-mcp",
  "mcp-grafana-npx": "mcp-grafana-npx",
  "terraform-mcp-server": "terraform-mcp-server",
  "swagger-mcp": "swagger-mcp",
  "openapi-mcp-server": "openapi-mcp-server",
  "git-mcp": "git-mcp",
  "repl-mcp": "repl-mcp",
  "mcp-server-kubernetes-april": "mcp-server-kubernetes",
  "shopify-mcp-server": "shopify-mcp-server",
  "salesforce-mcp": "@salesforce/mcp",
  "sendgrid-mcp": "sendgrid-mcp",
  "mcp-linear": "mcp-linear",
  "quickbooks-mcp": "quickbooks-mcp",
  "hubspot-mcp-community": "hubspot-mcp",
  "vercel-mcp": "vercel-mcp",
  "twilio-mcp": "twilio-mcp",
  "redis-mcp": "redis-mcp",
  "mysql-mcp-server": "mysql-mcp-server",
  "discord-mcp": "discord-mcp",
  "gmail-mcp-server": "gmail-mcp-server",
  "aws-s3-mcp": "aws-s3-mcp",
  "trello-mcp": "trello-mcp",
  "airtable-mcp-server": "airtable-mcp-server",
  "gitlab-mcp": "gitlab-mcp",
  "hubspot-mcp": "hubspot-mcp",
  "salesforce-mcp-server": "salesforce-mcp-server",
  "pipedrive-mcp": "pipedrive-mcp",
  "splunk-mcp": "splunk-mcp",
  "datadog-mcp-server": "datadog-mcp-server",
  "wordpress-mcp": "wordpress-mcp",
  "shopify-admin-mcp": "shopify-admin-mcp",
  "strapi-mcp": "strapi-mcp",
  "bitwarden-mcp": "bitwarden-mcp",
  "home-assistant-mcp": "home-assistant-mcp",
  "stitch-mcp": "stitch-mcp",
  "opsgenie-mcp-server": "opsgenie-mcp-server",
  "reddit-mcp": "reddit-mcp",
  "youtube-mcp": "youtube-mcp",
  "linkedin-mcp": "linkedin-mcp",
  "binance-mcp": "binance-mcp",
  "mcp-server-linear": "mcp-server-linear",
  "mcp-server-trello": "mcp-server-trello",
  "notionhq-notion-mcp-server-v2": "@notionhq/notion-mcp-server",
  "linear-mcp-server": "linear-mcp-server",
  "pdf-mcp": "pdf-mcp",
  "mcp-shell": "mcp-shell",
  "mcp-server-commands": "mcp-server-commands",
  "bash-mcp": "bash-mcp",
  "shell-mcp": "shell-mcp",
  "apple-notes-mcp": "apple-notes-mcp",
  "joplin-mcp": "joplin-mcp",
  "omnifocus-mcp": "omnifocus-mcp",
  "google-meet-mcp": "google-meet-mcp",
  "reminders-mcp": "reminders-mcp",
  "ticktick-mcp": "ticktick-mcp",
  "hubspot-mcp": "hubspot-mcp",
  "salesforce-mcp-server": "salesforce-mcp-server",
  "pipedrive-mcp": "pipedrive-mcp",
  "splunk-mcp": "splunk-mcp",
  "datadog-mcp-server": "datadog-mcp-server",
  "wordpress-mcp": "wordpress-mcp",
  "shopify-admin-mcp": "shopify-admin-mcp",
};

const MAINTAINER_MAP = {
  "modelcontextprotocol-server-github": "Anthropic",
  "modelcontextprotocol-server-filesystem": "Anthropic",
  "modelcontextprotocol-server-puppeteer": "Anthropic",
  "modelcontextprotocol-server-memory": "Anthropic",
  "modelcontextprotocol-server-everything": "Anthropic",
  "modelcontextprotocol-server-postgres": "Anthropic",
  "modelcontextprotocol-server-fetch": "Anthropic",
  "modelcontextprotocol-server-brave-search": "Anthropic",
  "modelcontextprotocol-server-sequential-thinking": "Anthropic",
  "server-filesystem": "Anthropic",
  "server-memory": "Anthropic",
  "playwright-mcp": "Microsoft",
  "azure-mcp": "Microsoft",
  "microsoft-devbox-mcp": "Microsoft",
  "notionhq-notion-mcp-server": "Notion",
  "heroku-mcp-server": "Heroku",
  "supabase-mcp-server-supabase": "Supabase",
  "sentry-mcp-server": "Sentry",
  "cloudflare-mcp-server": "Cloudflare",
  "hubspot-mcp-server": "HubSpot",
  "composio-mcp": "Composio",
  "european-parliament-mcp-server": "EU Parliament",
  "figma-mcp": "Figma",
  "shopify-mcp-server": "Shopify",
  "sendgrid-mcp": "Twilio SendGrid",
  "twilio-mcp": "Twilio",
  "vercel-mcp": "Community",
  "quickbooks-mcp": "Community",
  "mcp-linear": "Community",
  "salesforce-mcp": "Salesforce",
  "hubspot-mcp-community": "Community",
  "gitlab-mcp": "Community",
  "trello-mcp": "Community",
  "airtable-mcp-server": "Community",
  "discord-mcp": "Community",
  "gmail-mcp-server": "Community",
  "redis-mcp": "Community",
  "mysql-mcp-server": "Community",
  "hubspot-mcp": "HubSpot",
  "salesforce-mcp-server": "Salesforce",
  "pipedrive-mcp": "Community",
  "splunk-mcp": "Community",
  "datadog-mcp-server": "Community",
  "wordpress-mcp": "Community",
  "shopify-admin-mcp": "Shopify",
  "bitwarden-mcp": "Community",
  "stitch-mcp": "Community",
  "opsgenie-mcp-server": "Community",
  "reddit-mcp": "Community",
  "youtube-mcp": "Community",
  "linkedin-mcp": "Community",
  "binance-mcp": "Community",
  "mcp-server-linear": "Community",
  "mcp-server-trello": "Community",
  "notionhq-notion-mcp-server-v2": "Notion",
  "linear-mcp-server": "Community",
  "pdf-mcp": "Community",
  "mcp-shell": "Community",
  "mcp-server-commands": "Community",
  "bash-mcp": "Community",
  "shell-mcp": "Community",
  "apple-notes-mcp": "Community",
  "joplin-mcp": "Community",
  "omnifocus-mcp": "Community",
  "google-meet-mcp": "Community",
  "reminders-mcp": "Community",
  "ticktick-mcp": "Community",
  "home-assistant-mcp": "Community",
  "hubspot-mcp": "HubSpot",
  "salesforce-mcp-server": "Salesforce",
  "pipedrive-mcp": "Community",
  "splunk-mcp": "Community",
  "datadog-mcp-server": "Community",
  "wordpress-mcp": "Community",
  "strapi-mcp": "Community",
  "exa-mcp-server": "Exa",
  "tavily-mcp": "Tavily",
  "upstash-context7-mcp": "Upstash",
};

function getMaintainer(slug) {
  return MAINTAINER_MAP[slug] ?? "Community";
}

function getNpmPackage(slug, serverName) {
  if (NPM_SLUG_MAP[slug]) return NPM_SLUG_MAP[slug];
  // Use server name if it looks like a package name
  if (serverName.startsWith("@")) return serverName;
  return slug.replace(/-/g, "-");
}

function enrichDescription(rule, tool, detail) {
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
      return detail; // already specific with counts
    case "conflicting_tool_descriptions":
      return detail; // already specific
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

function buildMapPolicy(findings) {
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

  // catch-all allow at the end
  rules.push({ tool: "*", action: "allow" });

  return JSON.stringify({ version: "1.0", rules }, null, 2);
}

function getRiskTags(riskProfile) {
  const tags = [];
  if ((riskProfile.destructive ?? 0) > 0) tags.push("destructive");
  if ((riskProfile.execution ?? 0) > 0) tags.push("execution");
  if ((riskProfile.deployment ?? 0) > 0) tags.push("deployment");
  if ((riskProfile.financial ?? 0) > 0) tags.push("financial");
  if ((riskProfile.privilege ?? 0) > 0) tags.push("privilege");
  if ((riskProfile.credential_access ?? 0) > 0) tags.push("credential_access");
  if ((riskProfile.mutation ?? 0) > 0) tags.push("mutation");
  return tags;
}

// Read all reports
const files = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"));
const servers = [];

for (const file of files) {
  const slug = file.replace(".json", "");
  const raw = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));

  const high = (raw.summary.HIGH ?? 0) + (raw.summary.CRITICAL ?? 0);
  const medium = raw.summary.MEDIUM ?? 0;
  const low = raw.summary.LOW ?? 0;

  const topFindings = (raw.findings ?? [])
    .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
    .slice(0, 4)
    .map((f) => ({
      severity: f.severity === "CRITICAL" ? "HIGH" : f.severity,
      category: f.category.toUpperCase(),
      tool: f.tool !== "*" ? f.tool : undefined,
      description: enrichDescription(f.rule, f.tool, f.detail),
    }));

  const mapPolicy = (raw.findings ?? []).length > 0
    ? buildMapPolicy(raw.findings)
    : null;

  servers.push({
    id: slug,
    package: getNpmPackage(slug, raw.server.name),
    name: raw.server.name,
    maintainer: getMaintainer(slug),
    version: raw.server.version ?? "unknown",
    tools: raw.toolCount ?? 0,
    score: raw.grade.score,
    grade: raw.grade.overall,
    categories: raw.grade.categories ?? {},
    findings: { high, medium, low },
    riskTags: getRiskTags(raw.riskProfile ?? {}),
    topFindings,
    mapPolicy,
    scannedAt: raw.scannedAt,
  });
}

// Sort: worst first (score asc, then high count desc)
servers.sort((a, b) => {
  if (a.score !== b.score) return a.score - b.score;
  return b.findings.high - a.findings.high;
});

const stats = {
  total: servers.length,
  withTools: servers.filter((s) => s.tools > 0).length,
  fGrade: servers.filter((s) => s.grade === "F").length,
  totalFindings: servers.reduce((acc, s) => acc + s.findings.high + s.findings.medium + s.findings.low, 0),
  totalTools: servers.reduce((acc, s) => acc + s.tools, 0),
};

const output = `// AUTO-GENERATED by scripts/generate-hall-data.mjs
// Do not edit manually — run: node scripts/generate-hall-data.mjs

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface HallFinding {
  readonly severity: "HIGH" | "MEDIUM" | "LOW";
  readonly category: string;
  readonly tool?: string;
  readonly description: string;
}

export interface HallServer {
  readonly id: string;
  readonly package: string;
  readonly name: string;
  readonly maintainer: string;
  readonly version: string;
  readonly tools: number;
  readonly score: number;
  readonly grade: Grade;
  readonly categories: Partial<Record<string, Grade>>;
  readonly findings: { readonly high: number; readonly medium: number; readonly low: number };
  readonly riskTags: readonly string[];
  readonly topFindings: readonly HallFinding[];
  readonly mapPolicy: string | null;
  readonly scannedAt: string;
}

export interface HallStats {
  readonly total: number;
  readonly withTools: number;
  readonly fGrade: number;
  readonly totalFindings: number;
  readonly totalTools: number;
}

export const HALL_STATS: HallStats = ${JSON.stringify(stats, null, 2)};

export const HALL_SERVERS: readonly HallServer[] = ${JSON.stringify(servers, null, 2)} as const;
`;

fs.writeFileSync(OUT_FILE, output);
console.log(`✓ Generated ${OUT_FILE}`);
console.log(`  ${servers.length} servers | ${stats.withTools} with tools | ${stats.fGrade} F grades`);
console.log(`  ${stats.totalFindings} total findings across ${stats.totalTools} tools`);
