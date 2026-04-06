#!/usr/bin/env node
/**
 * Census-wide decode of the 145 hidden_characters findings.
 *
 * Reads every report in scanner/reports/ that contains a hidden_characters
 * finding, looks up the package command in scanner/scripts/server-list.json,
 * spawns each server via MCP stdio, calls tools/list, and classifies every
 * hidden codepoint in every affected tool description by encoding scheme.
 *
 * Reuses the classification pattern from analysis.mjs and the decode helpers
 * from unicode-encode.mjs.
 *
 * Output: census-decode.json (full dataset) + summary table to stdout.
 *
 * Usage:
 *   node docs/census-2026/poc/census-decode.mjs
 *   node docs/census-2026/poc/census-decode.mjs --limit 10
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { decodeTagBlock, decodeZeroWidth } from "./unicode-encode.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_ROOT = path.resolve(__dirname, "../../..");
const REPORTS_DIR = path.join(SCANNER_ROOT, "reports");
const SERVER_LIST = path.join(SCANNER_ROOT, "scripts/server-list.json");
const OUT_FILE = path.join(__dirname, "census-decode.json");

const args = process.argv.slice(2);
const LIMIT = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : null;
const TIMEOUT = 30000;

// ─── Codepoint classification (lifted from analysis.mjs) ───

function classifyCodepoint(cp) {
  if (cp >= 0xe0000 && cp <= 0xe007f) return "tag_block";          // Goodside 2024
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d) return "zero_width"; // ZWSP/ZWNJ/ZWJ
  if (cp === 0xfeff) return "bom";
  if (cp >= 0xfe00 && cp <= 0xfe0f) return "variation_selector";   // 16 selectors
  if (cp >= 0xe0100 && cp <= 0xe01ef) return "variation_selector_supp"; // supplementary 240
  if (cp >= 0x202a && cp <= 0x202e) return "bidi_control";         // LRE/RLE/PDF/LRO/RLO
  if (cp >= 0x2066 && cp <= 0x2069) return "bidi_isolate";         // LRI/RLI/FSI/PDI
  if (cp === 0x200e || cp === 0x200f) return "lrm_rlm";
  if (cp === 0x2062 || cp === 0x2064) return "sneaky_bits";        // Rehberger 2025
  if (cp >= 0x180b && cp <= 0x180d) return "mongolian_fvs";
  return null;
}

function classifyDescription(raw) {
  const classes = {};
  const rawPoints = [];
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    const klass = classifyCodepoint(cp);
    if (klass) {
      classes[klass] = (classes[klass] || 0) + 1;
      rawPoints.push(cp);
    }
  }
  return { classes, rawPoints, hiddenCount: rawPoints.length };
}

// ─── Attempt to decode the hidden payload ───

function attemptDecode(raw, classes) {
  const decoded = {};
  if (classes.tag_block) decoded.tag_block = decodeTagBlock(raw);
  if (classes.zero_width && classes.zero_width >= 8) {
    const zw = [...raw].filter((ch) => {
      const cp = ch.codePointAt(0);
      return cp === 0x200b || cp === 0x200c || cp === 0x200d;
    }).join("");
    try {
      decoded.zero_width = decodeZeroWidth(zw);
    } catch {}
  }
  if (classes.variation_selector || classes.variation_selector_supp) {
    const bytes = [...raw]
      .map((ch) => ch.codePointAt(0))
      .filter((cp) =>
        (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)
      )
      .map((cp) => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16));
    decoded.variation_selector = Buffer.from(bytes).toString("utf8");
  }
  return decoded;
}

// ─── Load affected reports ───

function loadAffectedReports() {
  const affected = [];
  const files = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"));
  for (const file of files) {
    const full = path.join(REPORTS_DIR, file);
    let data;
    try {
      data = JSON.parse(fs.readFileSync(full, "utf8"));
    } catch {
      continue;
    }
    const hiddenFindings = (data.findings || []).filter((f) => f.rule === "hidden_characters");
    if (hiddenFindings.length === 0) continue;
    affected.push({
      reportFile: file,
      serverName: data.server?.name,
      hiddenTools: hiddenFindings.map((f) => f.tool),
      findingCount: hiddenFindings.length,
    });
  }
  return affected;
}

// ─── Map report filenames to server-list.json commands ───

function buildCommandMap() {
  const list = JSON.parse(fs.readFileSync(SERVER_LIST, "utf8"));
  const map = new Map();
  for (const s of list.servers) {
    // Reports are named like "npm-@ateam-ai-mcp.json" → package "@ateam-ai/mcp"
    // or "pypi-something.json"
    map.set(s.id, s);
    map.set(s.name, s);
    map.set(s.package, s);
  }
  return map;
}

function reportFileToServer(file, cmdMap) {
  // Strip extension, split prefix
  const base = file.replace(/\.json$/, "");
  const dashIdx = base.indexOf("-");
  if (dashIdx === -1) return null;
  const prefix = base.slice(0, dashIdx);
  const rest = base.slice(dashIdx + 1);

  // Direct id match
  const id = `${prefix}:${rest}`;
  if (cmdMap.has(id)) return cmdMap.get(id);

  // Try reconstructing scoped packages: "@ateam-ai-mcp" → try "@ateam-ai/mcp"
  if (rest.startsWith("@")) {
    const parts = rest.slice(1).split("-");
    for (let i = 1; i < parts.length; i++) {
      const scope = parts.slice(0, i).join("-");
      const pkgName = parts.slice(i).join("-");
      const candidate = `@${scope}/${pkgName}`;
      if (cmdMap.has(`${prefix}:${candidate}`)) return cmdMap.get(`${prefix}:${candidate}`);
      if (cmdMap.has(candidate)) return cmdMap.get(candidate);
    }
  }

  // Fallback: search by suffix
  for (const [key, val] of cmdMap) {
    if (key.endsWith(rest) && key.startsWith(prefix)) return val;
  }
  return null;
}

// ─── Spawn server and grab manifest ───

async function getToolManifest(server) {
  const parts = server.command.split(/\s+/);
  const transport = new StdioClientTransport({
    command: parts[0],
    args: parts.slice(1),
  });
  const client = new Client(
    { name: "census-decoder", version: "1.0.0" },
    { capabilities: {} }
  );
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("timeout")), TIMEOUT)
  );
  try {
    await Promise.race([client.connect(transport), timeoutPromise]);
    const result = await Promise.race([client.listTools(), timeoutPromise]);
    return result.tools || [];
  } finally {
    try { await client.close(); } catch {}
  }
}

// ─── Main ───

async function main() {
  console.log("\n  AgentSID Paper 5 — Census Decode");
  console.log("  Decoding 145 hidden_characters findings by codepoint class");
  console.log(`  ${new Date().toISOString()}\n`);

  const affected = loadAffectedReports();
  console.log(`  Found ${affected.length} servers with hidden_characters findings`);
  const totalFindings = affected.reduce((a, s) => a + s.findingCount, 0);
  console.log(`  Total findings: ${totalFindings}\n`);

  const cmdMap = buildCommandMap();
  const targets = LIMIT ? affected.slice(0, LIMIT) : affected;

  const results = {
    meta: {
      generatedAt: new Date().toISOString(),
      affectedServers: affected.length,
      totalFindings,
    },
    classSummary: {},
    servers: [],
    unresolved: [],
    errors: [],
  };

  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const server = reportFileToServer(target.reportFile, cmdMap);
    const label = `[${i + 1}/${targets.length}] ${target.reportFile}`;
    if (!server) {
      console.log(`  ${label} — UNRESOLVED in server-list.json`);
      results.unresolved.push(target.reportFile);
      continue;
    }

    console.log(`  ${label}`);
    console.log(`    command: ${server.command}`);

    let tools;
    try {
      tools = await getToolManifest(server);
    } catch (e) {
      console.log(`    ERROR: ${e.message}`);
      results.errors.push({ report: target.reportFile, command: server.command, error: e.message });
      continue;
    }

    const serverResult = {
      report: target.reportFile,
      serverName: target.serverName,
      package: server.package,
      command: server.command,
      tools: [],
    };

    for (const tool of tools) {
      const raw = tool.description || "";
      const { classes, rawPoints, hiddenCount } = classifyDescription(raw);
      if (hiddenCount === 0) continue;

      const decoded = attemptDecode(raw, classes);
      const visible = raw
        .replace(/[\u{E0000}-\u{E007F}]/gu, "")
        .replace(/[\u200B\u200C\u200D\uFEFF]/g, "")
        .replace(/[\uFE00-\uFE0F]/g, "")
        .replace(/[\u{E0100}-\u{E01EF}]/gu, "")
        .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, "")
        .replace(/[\u2062\u2064]/g, "")
        .replace(/[\u180B-\u180D]/g, "");

      serverResult.tools.push({
        tool: tool.name,
        hiddenCount,
        rawLength: [...raw].length,
        visibleLength: [...visible].length,
        classes,
        rawCodepoints: rawPoints.map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`),
        visible: visible.substring(0, 200),
        decoded,
      });

      for (const [klass, count] of Object.entries(classes)) {
        results.classSummary[klass] = (results.classSummary[klass] || 0) + count;
      }

      console.log(`    tool: ${tool.name} — ${hiddenCount} hidden (${Object.keys(classes).join(", ")})`);
      for (const [scheme, payload] of Object.entries(decoded)) {
        if (payload && payload.trim()) {
          const preview = payload.substring(0, 120).replace(/\n/g, " ");
          console.log(`      [${scheme}] "${preview}"`);
        }
      }
    }

    results.servers.push(serverResult);
  }

  fs.writeFileSync(OUT_FILE, JSON.stringify(results, null, 2));

  console.log("\n  ═══ Summary ═══\n");
  console.log(`  Servers scanned: ${targets.length}`);
  console.log(`  Servers resolved: ${results.servers.length}`);
  console.log(`  Unresolved: ${results.unresolved.length}`);
  console.log(`  Errors: ${results.errors.length}`);
  console.log(`\n  Codepoint class distribution (total occurrences):`);
  const sorted = Object.entries(results.classSummary).sort((a, b) => b[1] - a[1]);
  for (const [klass, count] of sorted) {
    console.log(`    ${klass.padEnd(28)} ${count}`);
  }
  console.log(`\n  Output: ${OUT_FILE}\n`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
