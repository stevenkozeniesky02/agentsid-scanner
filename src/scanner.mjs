/**
 * MCP Server Scanner — connects to an MCP server, enumerates tools,
 * and runs security analysis across all rule categories.
 *
 * Supports stdio and HTTP transport modes.
 */

import { spawn } from "child_process";
import {
  scanToolDescriptions,
  scanToolNames,
  scanInputSchemas,
  scanAuthIndicators,
  scanOutputSafety,
  scanHallucinationRisks,
  scanToxicDataFlows,
} from "./rules.mjs";
import { grade } from "./grader.mjs";
import { formatTerminalReport, formatJsonReport, formatHtmlReport } from "./reporter.mjs";
import { buildMapPolicy, enrichDescription } from "./policy.mjs";
import { auditSupplyChain } from "./audit.mjs";

/**
 * Scan an MCP server by spawning it as a subprocess (stdio transport).
 * @param {string} command — Command to start the server (e.g., "npx @some/mcp-server")
 * @param {object} options — { env, timeout, json }
 */
export async function scanStdio(command, options = {}) {
  const { env = {}, timeout = 30000, json = false, policy = false, html = false, audit = false } = options;

  const parts = command.split(/\s+/);
  const proc = spawn(parts[0], parts.slice(1), {
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const result = await communicateWithServer(proc, timeout);
  proc.kill();

  const supplyChainFindings = audit ? await auditSupplyChain(command) : [];
  return generateReport(result.serverInfo, result.tools, json, policy, html, supplyChainFindings);
}

/**
 * Scan an MCP server by connecting over HTTP (streamable HTTP transport).
 * @param {string} url — Server URL
 * @param {object} options — { headers, timeout, json }
 */
export async function scanHttp(url, options = {}) {
  const { headers = {}, timeout = 30000, json = false, policy = false, html = false } = options;
  // Supply chain audit not supported for HTTP transport — no package to resolve

  // For HTTP transport, we send JSON-RPC over HTTP
  const initResponse = await fetchRpc(url, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "agentsid-scanner", version: "0.1.0" },
  }, headers, timeout);

  const serverInfo = initResponse?.result?.serverInfo || { name: "unknown", version: "?" };

  // Send initialized notification
  await fetchRpc(url, "notifications/initialized", {}, headers, timeout);

  // List tools
  const toolsResponse = await fetchRpc(url, "tools/list", {}, headers, timeout);
  const tools = toolsResponse?.result?.tools || [];

  return generateReport(serverInfo, tools, json, policy, html);
}

/**
 * Scan from a tool definition list (no server connection needed).
 * Useful for scanning tool configs or package.json MCP definitions.
 * @param {Array} tools — Array of tool definition objects
 * @param {object} options — { serverName, json }
 */
export function scanToolDefinitions(tools, options = {}) {
  const { serverName = "static-analysis", json = false, policy = false, html = false } = options;
  const serverInfo = { name: serverName, version: "static" };
  return generateReport(serverInfo, tools, json, policy, html, []);
}

// ─── Internal ───

async function communicateWithServer(proc, timeout) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const responses = {};

    proc.stdout.on("data", (data) => {
      buf += data.toString();
      while (buf.includes("\n")) {
        const idx = buf.indexOf("\n");
        const line = buf.substring(0, idx);
        buf = buf.substring(idx + 1);
        try {
          const msg = JSON.parse(line);
          if (msg.id) responses[msg.id] = msg;
        } catch {}
      }
    });

    proc.stderr.on("data", () => {}); // Suppress stderr

    // Send initialize
    proc.stdin.write(JSON.stringify({
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "agentsid-scanner", version: "0.1.0" },
      },
      id: 1,
    }) + "\n");

    setTimeout(() => {
      // Send initialized notification
      proc.stdin.write(JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {},
      }) + "\n");
    }, 500);

    setTimeout(() => {
      // List tools
      proc.stdin.write(JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/list",
        params: {},
        id: 2,
      }) + "\n");
    }, 1000);

    // Wait for tools/list response
    const check = setInterval(() => {
      if (responses[2]) {
        clearInterval(check);
        clearTimeout(timer);

        const serverInfo = responses[1]?.result?.serverInfo || { name: "unknown", version: "?" };
        const tools = responses[2]?.result?.tools || [];

        resolve({ serverInfo, tools });
      }
    }, 100);

    const timer = setTimeout(() => {
      clearInterval(check);
      const serverInfo = responses[1]?.result?.serverInfo || { name: "unknown", version: "?" };
      const tools = responses[2]?.result?.tools || [];
      resolve({ serverInfo, tools });
    }, timeout);
  });
}

async function fetchRpc(url, method, params, headers, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method,
        params,
        id: Math.floor(Math.random() * 10000),
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return response.json();
  } catch (err) {
    clearTimeout(timer);
    return null;
  }
}

function generateReport(serverInfo, tools, json, includePolicy, html, supplyChainFindings = []) {
  // Run all scan rules
  const descriptionFindings = scanToolDescriptions(tools);
  const { findings: nameFindings, riskProfile } = scanToolNames(tools);
  const schemaFindings = scanInputSchemas(tools);
  const authFindings = scanAuthIndicators(tools, serverInfo);
  const outputFindings = scanOutputSafety(tools);
  const hallucinationFindings = scanHallucinationRisks(tools);
  const toxicFlowFindings = scanToxicDataFlows(tools);

  // Combine all findings — supply chain and toxic flows first so CRITICALs surface early
  const allFindings = [
    ...supplyChainFindings,
    ...toxicFlowFindings,
    ...descriptionFindings,
    ...nameFindings,
    ...schemaFindings,
    ...authFindings,
    ...outputFindings,
    ...hallucinationFindings,
  ];

  // Grade
  const gradeResult = grade(allFindings);

  // Build policy if requested
  const mapPolicy = includePolicy ? buildMapPolicy(allFindings) : null;

  // Enrich finding descriptions
  const enrichedFindings = allFindings.map((f) => ({
    ...f,
    detail: enrichDescription(f.rule, f.tool, f.detail),
  }));

  // Format report
  if (json) {
    return formatJsonReport(serverInfo, tools, enrichedFindings, gradeResult, riskProfile, mapPolicy);
  }
  if (html) {
    return formatHtmlReport(serverInfo, tools, enrichedFindings, gradeResult, riskProfile, mapPolicy);
  }
  return formatTerminalReport(serverInfo, tools, enrichedFindings, gradeResult, riskProfile, mapPolicy);
}
