#!/usr/bin/env node
/**
 * Wide-spectrum census decode — check UNFLAGGED servers for blind-spot codepoints.
 *
 * The scanner's hidden_characters rule only strips a subset of invisible codepoints
 * (tag block, zero-width, basic variation selectors, BiDi, LRM/RLM). It does NOT
 * strip supplementary-plane variation selectors (U+E0100-E01EF — the Graves scheme),
 * sneaky bits (U+2062/2064), Mongolian FVS, word joiner, soft hyphen, etc.
 *
 * Any server using these classes would not trigger hidden_characters and would
 * not appear in census-decode.json. This script samples unflagged servers and
 * looks for blind-spot codepoints directly in the tools/list manifest.
 *
 * Usage:
 *   node docs/census-2026/poc/census-decode-wide.mjs --sample 100
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_ROOT = path.resolve(__dirname, "../../..");
const REPORTS_DIR = path.join(SCANNER_ROOT, "reports");
const SERVER_LIST = path.join(SCANNER_ROOT, "scripts/server-list.json");
const OUT_FILE = path.join(__dirname, "census-decode-wide.json");

const args = process.argv.slice(2);
const SAMPLE = args.includes("--sample") ? parseInt(args[args.indexOf("--sample") + 1]) : 100;
const TIMEOUT = 30000;

// Classes scanner ALREADY strips — we don't re-report these
function isStripped(cp) {
  return (
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x200e || cp === 0x200f
  );
}

// Blind-spot classes the scanner misses
function classifyBlindSpot(cp) {
  if (cp >= 0xe0100 && cp <= 0xe01ef) return "variation_selector_supp_graves";
  if (cp === 0x2062) return "sneaky_bits_invisible_times";
  if (cp === 0x2064) return "sneaky_bits_invisible_plus";
  if (cp === 0x2060) return "word_joiner";
  if (cp === 0x2061) return "function_application";
  if (cp === 0x2063) return "invisible_separator";
  if (cp >= 0x180b && cp <= 0x180d) return "mongolian_fvs";
  if (cp === 0x00ad) return "soft_hyphen";
  if (cp === 0x034f) return "combining_grapheme_joiner";
  if (cp >= 0x115f && cp <= 0x1160) return "hangul_choseong_filler";
  if (cp === 0x3164) return "hangul_filler";
  if (cp === 0xffa0) return "halfwidth_hangul_filler";
  if (cp >= 0xe000 && cp <= 0xf8ff) return "pua_bmp";
  if (cp >= 0xf0000 && cp <= 0xffffd) return "pua_supp_a";
  if (cp >= 0x100000 && cp <= 0x10fffd) return "pua_supp_b";
  return null;
}

function classifyTool(tool) {
  const hits = [];
  function walk(s, field) {
    if (typeof s !== "string") return;
    for (let i = 0; i < s.length; i++) {
      const cp = s.codePointAt(i);
      if (cp > 0xffff) i++; // surrogate
      if (cp < 0x80 || isStripped(cp)) continue;
      const klass = classifyBlindSpot(cp);
      if (klass) hits.push({ klass, cp, field, offset: i, snippet: s.slice(Math.max(0, i - 20), i + 20) });
    }
  }
  walk(tool.description, "description");
  walk(tool.name, "name");
  if (tool.inputSchema?.properties) {
    for (const [pname, pschema] of Object.entries(tool.inputSchema.properties)) {
      walk(pschema.description, `param:${pname}`);
      walk(pschema.title, `param:${pname}.title`);
    }
  }
  return hits;
}

function loadFlaggedServers() {
  const flagged = new Set();
  for (const file of fs.readdirSync(REPORTS_DIR)) {
    if (!file.endsWith(".json")) continue;
    try {
      const data = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
      if ((data.findings || []).some((f) => f.rule === "hidden_characters")) {
        flagged.add(file.replace(/\.json$/, ""));
      }
    } catch {}
  }
  return flagged;
}

function sampleUnflagged(flagged, n) {
  // Pull from reports/ so we only sample servers known to have successfully scanned.
  // Also prefer servers with tools > 0 and CRITICAL/HIGH findings (likely targets).
  const list = JSON.parse(fs.readFileSync(SERVER_LIST, "utf8"));
  const byPackage = new Map();
  const byName = new Map();
  for (const s of list.servers) {
    if (s.package) byPackage.set(s.package, s);
    if (s.name) byName.set(s.name, s);
  }
  const candidates = [];
  for (const file of fs.readdirSync(REPORTS_DIR)) {
    if (!file.endsWith(".json")) continue;
    const key = file.replace(/\.json$/, "");
    if (flagged.has(key)) continue;
    let data;
    try {
      data = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
    } catch { continue; }
    if (!data.toolCount || data.toolCount < 1) continue;
    // Find the matching server in the list via package name
    const pkg = data.server?.name;
    const server = byPackage.get(pkg) || byName.get(pkg);
    if (!server || !server.command) continue;
    // Prefer servers with CRITICAL or HIGH findings — these are likely targets
    const criticalOrHigh = (data.findings || []).filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length;
    candidates.push({ server, score: criticalOrHigh, toolCount: data.toolCount });
  }
  // Shuffle
  for (let i = candidates.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
  }
  // Sort by score desc, tie-broken by random shuffle
  candidates.sort((a, b) => b.score - a.score);
  return candidates.slice(0, n).map((c) => c.server);
}

async function getManifest(server) {
  const parts = server.command.split(/\s+/);
  const transport = new StdioClientTransport({ command: parts[0], args: parts.slice(1) });
  const client = new Client({ name: "wide-decoder", version: "1.0.0" }, { capabilities: {} });
  const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), TIMEOUT));
  try {
    await Promise.race([client.connect(transport), timeoutPromise]);
    const result = await Promise.race([client.listTools(), timeoutPromise]);
    return result.tools || [];
  } finally {
    try { await client.close(); } catch {}
  }
}

async function main() {
  console.log("\n  AgentSID Paper 5 — Wide Census Decode (Blind Spot Hunt)");
  console.log(`  Sample size: ${SAMPLE} unflagged servers`);
  console.log(`  ${new Date().toISOString()}\n`);

  const flagged = loadFlaggedServers();
  console.log(`  Flagged servers (excluded): ${flagged.size}`);

  const sample = sampleUnflagged(flagged, SAMPLE);
  console.log(`  Unflagged sample: ${sample.length}\n`);

  const results = {
    meta: { generatedAt: new Date().toISOString(), sampleSize: sample.length },
    classSummary: {},
    hits: [],
    errors: 0,
    scanned: 0,
  };

  for (let i = 0; i < sample.length; i++) {
    const server = sample[i];
    const label = `[${i + 1}/${sample.length}] ${server.id}`;
    let tools;
    try {
      tools = await getManifest(server);
    } catch (e) {
      console.log(`  ${label} — ERROR ${e.message.slice(0, 50)}`);
      results.errors++;
      continue;
    }
    results.scanned++;
    let serverHits = 0;
    for (const tool of tools) {
      const hits = classifyTool(tool);
      if (hits.length > 0) {
        serverHits += hits.length;
        results.hits.push({
          server: server.id,
          package: server.package,
          tool: tool.name,
          hits: hits.slice(0, 10),
        });
        for (const h of hits) {
          results.classSummary[h.klass] = (results.classSummary[h.klass] || 0) + 1;
        }
      }
    }
    if (serverHits > 0) {
      console.log(`  ${label} — ★ ${serverHits} blind-spot codepoints across ${tools.length} tools`);
    }
  }

  fs.writeFileSync(OUT_FILE, JSON.stringify(results, null, 2));

  console.log("\n  ═══ Summary ═══\n");
  console.log(`  Scanned: ${results.scanned}`);
  console.log(`  Errors: ${results.errors}`);
  console.log(`  Servers with blind-spot hits: ${new Set(results.hits.map((h) => h.server)).size}`);
  console.log(`\n  Class distribution:`);
  const sorted = Object.entries(results.classSummary).sort((a, b) => b[1] - a[1]);
  if (sorted.length === 0) console.log("    (none)");
  for (const [klass, count] of sorted) console.log(`    ${klass.padEnd(36)} ${count}`);
  console.log(`\n  Output: ${OUT_FILE}\n`);
}

main().catch((e) => { console.error(e); process.exit(1); });
