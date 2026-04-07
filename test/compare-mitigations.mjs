#!/usr/bin/env node

/**
 * Compare scanner results with and without mitigations.
 *
 * Feeds sample tool definitions through the scan pipeline twice:
 * once with mitigations, once without. Outputs a diff table.
 *
 * Usage: node test/compare-mitigations.mjs
 */

import {
  scanToolDescriptions,
  scanToolNames,
  scanInputSchemas,
  scanAuthIndicators,
  scanOutputSafety,
  scanHallucinationRisks,
  scanToxicDataFlows,
} from "../src/rules.mjs";
import { grade } from "../src/grader.mjs";
import { applyMitigations } from "../src/mitigations.mjs";

// ── Test Servers ────────────────────────────────────────────────

const TEST_SERVERS = [
  {
    name: "false-positive-heavy",
    desc: "Server designed to trigger false positives",
    serverInfo: { name: "cache-manager", version: "1.0.0" },
    tools: [
      {
        name: "delete_expired_cache",
        description: "A simple utility to clean up expired cache entries from the local store",
        inputSchema: {
          type: "object",
          properties: {
            older_than_hours: { type: "number", minimum: 1, maximum: 720 },
          },
          required: ["older_than_hours"],
        },
      },
      {
        name: "get_token_expiry",
        description: "Returns the expiration timestamp of the current authentication token",
        inputSchema: {
          type: "object",
          properties: {
            token_id: { type: "string", pattern: "^tok_[a-zA-Z0-9]+$" },
          },
          required: ["token_id"],
        },
      },
      {
        name: "manage_sessions",
        description: "Handle user session lifecycle",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["list", "revoke"] },
            session_id: { type: "string" },
          },
          required: ["action"],
        },
      },
      {
        name: "list_users",
        description: "List all users in the system",
        inputSchema: {
          type: "object",
          properties: {
            page: { type: "number", minimum: 1 },
            limit: { type: "number", minimum: 1, maximum: 100 },
          },
        },
      },
      {
        name: "get_status",
        description: "",
        inputSchema: {},
      },
    ],
  },
  {
    name: "legitimately-dangerous",
    desc: "Server with real security issues",
    serverInfo: { name: "admin-tools", version: "0.1.0" },
    tools: [
      {
        name: "execute_sql",
        description: "Run any SQL query against the production database",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
        },
      },
      {
        name: "send_email",
        description: "Send an email to any address with any content",
        inputSchema: {
          type: "object",
          properties: {
            to: { type: "string" },
            subject: { type: "string" },
            body: { type: "string" },
          },
        },
      },
      {
        name: "read_file",
        description: "Read any file from the filesystem",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
        },
      },
      {
        name: "admin_panel",
        description: "A simple helper for admin tasks",
        inputSchema: {},
      },
    ],
  },
  {
    name: "github-integration",
    desc: "Typical GitHub MCP server with many read tools",
    serverInfo: { name: "github-mcp", version: "2.0.0" },
    tools: [
      { name: "list_repos", description: "List repositories for the authenticated user", inputSchema: { type: "object", properties: { page: { type: "number" } } } },
      { name: "get_repo", description: "Get details of a specific repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" } }, required: ["owner", "repo"] } },
      { name: "list_issues", description: "List issues in a GitHub repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, state: { type: "string", enum: ["open", "closed", "all"] } }, required: ["owner", "repo"] } },
      { name: "get_issue", description: "Get a specific issue by number", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, number: { type: "number" } }, required: ["owner", "repo", "number"] } },
      { name: "list_pull_requests", description: "List pull requests in a repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" } }, required: ["owner", "repo"] } },
      { name: "get_pull_request", description: "Get a specific pull request", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, number: { type: "number" } }, required: ["owner", "repo", "number"] } },
      { name: "search_code", description: "Search code across GitHub repositories using the GitHub search API", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
      { name: "list_commits", description: "List commits in a repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" } }, required: ["owner", "repo"] } },
      { name: "get_file_contents", description: "Get the contents of a file in a repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, path: { type: "string" } }, required: ["owner", "repo", "path"] } },
      { name: "create_issue", description: "Create a new issue in a repository", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, title: { type: "string" }, body: { type: "string" } }, required: ["owner", "repo", "title"] } },
      { name: "create_pull_request", description: "Create a new pull request", inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" }, title: { type: "string" }, head: { type: "string" }, base: { type: "string" } }, required: ["owner", "repo", "title", "head", "base"] } },
      { name: "send_notification", description: "Send a notification to a configured Slack webhook", inputSchema: { type: "object", properties: { message: { type: "string", maxLength: 500 } }, required: ["message"] } },
      ...Array.from({ length: 10 }, (_, i) => ({
        name: `list_${["branches", "tags", "releases", "workflows", "actions", "labels", "milestones", "projects", "teams", "members"][i]}`,
        description: `List ${["branches", "tags", "releases", "workflows", "actions", "labels", "milestones", "projects", "teams", "members"][i]} for the repository`,
        inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" } }, required: ["owner", "repo"] },
      })),
    ],
  },
];

// ── Run Comparison ──────────────────────────────────────────────

function runScan(tools, serverInfo) {
  const descriptionFindings = scanToolDescriptions(tools);
  const { findings: nameFindings } = scanToolNames(tools);
  const schemaFindings = scanInputSchemas(tools);
  const authFindings = scanAuthIndicators(tools, serverInfo);
  const outputFindings = scanOutputSafety(tools);
  const hallucinationFindings = scanHallucinationRisks(tools);
  const toxicFlowFindings = scanToxicDataFlows(tools);

  return [
    ...toxicFlowFindings,
    ...descriptionFindings,
    ...nameFindings,
    ...schemaFindings,
    ...authFindings,
    ...outputFindings,
    ...hallucinationFindings,
  ];
}

console.log("═══════════════════════════════════════════════════════════");
console.log("  Scanner Mitigation Comparison Test");
console.log("═══════════════════════════════════════════════════════════\n");

for (const server of TEST_SERVERS) {
  const rawFindings = runScan(server.tools, server.serverInfo);
  const mitigatedFindings = applyMitigations(rawFindings, server.tools, server.serverInfo);

  const rawGrade = grade(rawFindings, server.tools.length);
  const mitigatedGrade = grade(mitigatedFindings, server.tools.length);

  console.log(`\n── ${server.name} (${server.desc}) ──`);
  console.log(`   Tools: ${server.tools.length}`);
  console.log(`   Raw:       ${rawGrade.letter} (${rawGrade.score}/100) — ${rawFindings.length} findings`);
  console.log(`   Mitigated: ${mitigatedGrade.letter} (${mitigatedGrade.score}/100) — ${mitigatedFindings.length} findings`);
  console.log(`   Delta:     ${mitigatedGrade.score - rawGrade.score > 0 ? "+" : ""}${mitigatedGrade.score - rawGrade.score} points`);

  // Show adjustments
  const adjusted = mitigatedFindings.filter((f) => f.originalSeverity);
  if (adjusted.length > 0) {
    console.log(`\n   Severity adjustments:`);
    for (const f of adjusted) {
      console.log(`     ${f.tool}: ${f.rule} — ${f.originalSeverity} → ${f.severity} (${f.confidence} confidence)`);
    }
  }

  // Show confidence distribution
  const confDist = { high: 0, medium: 0, low: 0 };
  for (const f of mitigatedFindings) {
    confDist[f.confidence || "high"]++;
  }
  console.log(`\n   Confidence: ${confDist.high} high, ${confDist.medium} medium, ${confDist.low} low`);
}

console.log("\n═══════════════════════════════════════════════════════════\n");
