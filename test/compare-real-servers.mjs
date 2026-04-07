#!/usr/bin/env node

/**
 * Compare mitigation impact on real MCP servers.
 *
 * Scans a set of well-known servers, captures tool definitions,
 * then runs findings through both raw and mitigated pipelines.
 *
 * Usage: node test/compare-real-servers.mjs
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
} from "../src/rules.mjs";
import { grade } from "../src/grader.mjs";
import { applyMitigations } from "../src/mitigations.mjs";

const SERVERS = [
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/server-fetch",
  "@playwright/mcp-server",
  "@anthropic/claude-code-mcp",
  "mcp-server-sqlite",
];

async function getTools(command, timeout = 20000) {
  return new Promise((resolve) => {
    const parts = command.split(/\s+/);
    const proc = spawn(parts[0], parts.slice(1), {
      env: { ...process.env },
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });

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

    proc.stderr.on("data", () => {});

    proc.stdin.write(JSON.stringify({
      jsonrpc: "2.0", method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0.1.0" } },
      id: 1,
    }) + "\n");

    setTimeout(() => {
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }) + "\n");
    }, 500);

    setTimeout(() => {
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "tools/list", params: {}, id: 2 }) + "\n");
    }, 1000);

    const timer = setTimeout(() => {
      const serverInfo = responses[1]?.result?.serverInfo || { name: command, version: "?" };
      const tools = responses[2]?.result?.tools || [];
      try { process.kill(-proc.pid, "SIGKILL"); } catch {}
      resolve({ serverInfo, tools, command });
    }, timeout);

    const check = setInterval(() => {
      if (responses[2]) {
        clearInterval(check);
        clearTimeout(timer);
        const serverInfo = responses[1]?.result?.serverInfo || { name: command, version: "?" };
        const tools = responses[2]?.result?.tools || [];
        try { process.kill(-proc.pid, "SIGKILL"); } catch {}
        resolve({ serverInfo, tools, command });
      }
    }, 100);
  });
}

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
console.log("  Real Server Mitigation Comparison");
console.log("═══════════════════════════════════════════════════════════\n");

const results = [];

for (const pkg of SERVERS) {
  process.stdout.write(`Scanning ${pkg}...`);
  try {
    const { serverInfo, tools, command } = await getTools(`npx -y ${pkg}`);
    if (tools.length === 0) {
      console.log(` SKIP (no tools returned)`);
      continue;
    }

    const rawFindings = runScan(tools, serverInfo);
    const mitigatedFindings = applyMitigations(rawFindings, tools, serverInfo);
    const rawGrade = grade(rawFindings, tools.length);
    const mitigatedGrade = grade(mitigatedFindings, tools.length);

    const delta = mitigatedGrade.score - rawGrade.score;
    const adjusted = mitigatedFindings.filter((f) => f.originalSeverity);
    const confDist = { high: 0, medium: 0, low: 0 };
    for (const f of mitigatedFindings) confDist[f.confidence || "high"]++;

    console.log(` ${tools.length} tools`);
    console.log(`  Raw:       ${rawGrade.letter} (${rawGrade.score}) | Mitigated: ${mitigatedGrade.letter} (${mitigatedGrade.score}) | Delta: ${delta >= 0 ? "+" : ""}${delta}`);
    console.log(`  Findings:  ${rawFindings.length} total | ${adjusted.length} adjusted | Confidence: ${confDist.high}H ${confDist.medium}M ${confDist.low}L`);

    if (adjusted.length > 0) {
      for (const f of adjusted.slice(0, 5)) {
        console.log(`    ${f.tool}: ${f.rule} ${f.originalSeverity}→${f.severity} (${f.confidence})`);
      }
      if (adjusted.length > 5) console.log(`    ... and ${adjusted.length - 5} more`);
    }
    console.log();

    results.push({ pkg, tools: tools.length, rawScore: rawGrade.score, rawGrade: rawGrade.letter, mitScore: mitigatedGrade.score, mitGrade: mitigatedGrade.letter, delta, adjusted: adjusted.length });
  } catch (err) {
    console.log(` ERROR: ${err.message}`);
  }
}

// Summary table
console.log("\n═══ Summary ═══════════════════════════════════════════════");
console.log("Package".padEnd(45) + "Tools  Raw    Mit    Delta  Adj");
console.log("─".repeat(75));
for (const r of results) {
  console.log(
    r.pkg.padEnd(45) +
    String(r.tools).padStart(3) + "   " +
    `${r.rawGrade}(${r.rawScore})`.padStart(6) + "  " +
    `${r.mitGrade}(${r.mitScore})`.padStart(6) + "  " +
    `${r.delta >= 0 ? "+" : ""}${r.delta}`.padStart(5) + "  " +
    String(r.adjusted).padStart(3)
  );
}
console.log("═══════════════════════════════════════════════════════════\n");
