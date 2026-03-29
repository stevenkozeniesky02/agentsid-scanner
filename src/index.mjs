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

import { scanStdio, scanHttp } from "./scanner.mjs";

// ─── Parse Args ───

const args = process.argv.slice(2);
let url = null;
let json = false;
let command = null;
let env = {};

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--url" && args[i + 1]) {
    url = args[++i];
  } else if (args[i] === "--json") {
    json = true;
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
  agentsid-scan -- <command>         Scan a local MCP server (stdio)
  agentsid-scan --url <url>          Scan a remote MCP server (HTTP)
  agentsid-scan --json -- <command>  Output JSON report

Options:
  --url <url>         Remote MCP server URL
  --json              Output JSON instead of terminal report
  --env KEY=VALUE     Set environment variable for the server
  --help, -h          Show this help

Examples:
  agentsid-scan -- npx @modelcontextprotocol/server-filesystem ./
  agentsid-scan -- npx @playwright/mcp-server
  agentsid-scan --url https://mcp.example.com/mcp
  agentsid-scan --json -- node my-server.mjs > report.json

Learn more: https://agentsid.dev/scanner
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
    let report;
    if (url) {
      report = await scanHttp(url, { json, timeout: 30000 });
    } else {
      report = await scanStdio(command, { env, json, timeout: 15000 });
    }

    console.log(report);
  } catch (err) {
    console.error(`Scan failed: ${err.message}`);
    process.exit(1);
  }
}

main();
