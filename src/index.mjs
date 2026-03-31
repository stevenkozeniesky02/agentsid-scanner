#!/usr/bin/env node

/**
 * AgentsID Security Scanner
 *
 * The Lighthouse of agent security. Scan any MCP server and get a
 * security report card with letter grades across auth, permissions,
 * input validation, injection risks, and output safety.
 *
 * Usage:
 *   npx @agentsid/scanner -- npx @some/mcp-server
 *   npx @agentsid/scanner --url https://mcp.example.com
 *   npx @agentsid/scanner --json -- node my-server.mjs
 *
 * Examples:
 *   agentsid-scan -- npx @modelcontextprotocol/server-filesystem ./
 *   agentsid-scan -- npx @playwright/mcp-server
 *   agentsid-scan --json -- python -m my_mcp_server > report.json
 */

import fs from "fs";
import { scanStdio, scanHttp } from "./scanner.mjs";
import { formatTerminalReport, formatHtmlReport } from "./reporter.mjs";

// ─── Parse Args ───

const args = process.argv.slice(2);
let url = null;
let json = false;
let policy = false;
let report = false;
let command = null;
let env = {};

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--url" && args[i + 1]) {
    url = args[++i];
  } else if (args[i] === "--json") {
    json = true;
  } else if (args[i] === "--policy") {
    policy = true;
  } else if (args[i] === "--report") {
    report = true;
  } else if (args[i] === "--env" && args[i + 1]) {
    const [k, v] = args[++i].split("=");
    env[k] = v;
  } else if (args[i] === "--help" || args[i] === "-h") {
    printHelp();
    process.exit(0);
  } else if (args[i] === "--") {
    command = args.slice(i + 1).join(" ");
    break;
  } else if (!args[i].startsWith("-")) {
    command = args.slice(i).join(" ");
    break;
  }
}

// ─── Help ───

function printHelp() {
  console.log(`
AgentsID Security Scanner v0.1.0
The Lighthouse of agent security.

Usage:
  agentsid-scan -- <command>                     Scan a local MCP server (stdio)
  agentsid-scan --url <url>                      Scan a remote MCP server (HTTP)
  agentsid-scan --json -- <command>              Output JSON report
  agentsid-scan --policy -- <command>            Scan + write agentsid.json policy file
  agentsid-scan --report -- <command>            Scan + write report.html (air-gap safe)
  agentsid-scan --policy --report -- <command>   Write both agentsid.json and report.html

Options:
  --url <url>         Remote MCP server URL
  --json              Output JSON instead of terminal report
  --policy            Generate agentsid.json policy file after scan
  --report            Generate self-contained report.html after scan
  --env KEY=VALUE     Set environment variable for the server
  --help, -h          Show this help

Examples:
  agentsid-scan -- npx @modelcontextprotocol/server-filesystem ./
  agentsid-scan -- npx @playwright/mcp-server
  agentsid-scan --url https://mcp.example.com/mcp
  agentsid-scan --policy -- node my-server.mjs
  agentsid-scan --report -- node my-server.mjs
  agentsid-scan --json -- node my-server.mjs > report.json

Learn more: https://agentsid.dev/docs
  `);
}

// ─── Run ───

async function main() {
  if (!url && !command) {
    console.error("Error: Provide a command (-- <command>) or URL (--url <url>) to scan.");
    console.error("Run with --help for usage.\n");
    process.exit(1);
  }

  if (!json) {
    console.error("\n🔍 AgentsID Security Scanner v0.1.0");
    console.error("   Scanning MCP server...\n");
  }

  try {
    // --policy and --report need JSON internally to extract structured data.
    const useJson = json || policy || report;

    let rawReport;
    if (url) {
      rawReport = await scanHttp(url, { json: useJson, policy, timeout: 30000 });
    } else {
      rawReport = await scanStdio(command, { env, json: useJson, policy, timeout: 15000 });
    }

    if (policy || report) {
      const parsed = JSON.parse(rawReport);

      if (policy && parsed.mapPolicy) {
        fs.writeFileSync("agentsid.json", JSON.stringify(parsed.mapPolicy, null, 2));
        console.error("✓ agentsid.json written");
      }

      if (report) {
        const { server, toolCount, findings, grade: g, riskProfile, mapPolicy: mp } = parsed;
        const gradeResult = {
          letter: g.overall,
          score: g.score,
          categoryGrades: g.categories,
          totalFindings: findings.length,
          critical: findings.filter((f) => f.severity === "CRITICAL").length,
          high: findings.filter((f) => f.severity === "HIGH").length,
          counts: findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {}),
        };
        const htmlOut = formatHtmlReport(server, Array(toolCount).fill({}), findings, gradeResult, riskProfile, mp);
        fs.writeFileSync("report.html", htmlOut);
        console.error("✓ report.html written");
      }

      if (!json) {
        const { server, toolCount, findings, grade: g, riskProfile } = parsed;
        const gradeResult = {
          letter: g.overall,
          score: g.score,
          categoryGrades: g.categories,
          totalFindings: findings.length,
          critical: findings.filter((f) => f.severity === "CRITICAL").length,
          high: findings.filter((f) => f.severity === "HIGH").length,
          counts: findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {}),
        };
        console.log(formatTerminalReport(server, Array(toolCount).fill({}), findings, gradeResult, riskProfile));
        return;
      }
    }

    console.log(rawReport);
  } catch (err) {
    console.error(`Scan failed: ${err.message}`);
    process.exit(1);
  }
}

main();
