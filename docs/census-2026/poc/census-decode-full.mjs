#!/usr/bin/env node
/**
 * Full census decode — extended sanitizer covering ALL invisible Unicode classes.
 *
 * This is the overnight version. It re-scans every server in scanner/reports/
 * (i.e., every server that previously produced a successful scan), spawns it
 * via MCP stdio transport, calls tools/list, and classifies every codepoint
 * in every tool description (and parameter description) across the full set
 * of invisible-Unicode classes — including the classes the production scanner's
 * hidden_characters rule DOES NOT strip.
 *
 * Classes the production scanner strips (redundant to re-report):
 *   U+E0000–E007F  Tag Block
 *   U+200B–200D    Zero-width
 *   U+FEFF         BOM
 *   U+FE00–FE0F    Variation Selector Basic
 *   U+202A–202E    BiDi Control
 *   U+2066–2069    BiDi Isolate
 *   U+200E, 200F   LRM/RLM
 *
 * Blind-spot classes the production scanner MISSES:
 *   U+E0100–E01EF  Variation Selector Supplementary (Graves 2026)
 *   U+2062, 2064   Sneaky Bits (Rehberger 2025)
 *   U+2060         Word Joiner
 *   U+2061         Function Application
 *   U+2063         Invisible Separator
 *   U+180B–180D    Mongolian Free Variation Selectors
 *   U+00AD         Soft Hyphen
 *   U+034F         Combining Grapheme Joiner
 *   U+115F, 1160   Hangul Choseong Filler
 *   U+3164         Hangul Filler
 *   U+FFA0         Halfwidth Hangul Filler
 *   U+E000–F8FF    Private Use Area BMP (excluding tag block)
 *   U+F0000–FFFFD  Supplementary PUA-A
 *   U+100000–10FFFD Supplementary PUA-B
 *
 * Features:
 *   - Resumable: incrementally writes census-decode-full.json, skips done servers
 *   - Parallel: configurable worker pool
 *   - Per-server timeout: 30s default
 *   - Reports BOTH stripped-class and blind-spot-class codepoints (stripped for
 *     cross-validation against production scanner, blind-spot for gap analysis)
 *
 * Usage:
 *   node docs/census-2026/poc/census-decode-full.mjs                   # 6 workers, resume
 *   node docs/census-2026/poc/census-decode-full.mjs --workers 10      # more parallelism
 *   node docs/census-2026/poc/census-decode-full.mjs --fresh           # ignore existing output
 *   node docs/census-2026/poc/census-decode-full.mjs --limit 500       # scan first N only
 *   node docs/census-2026/poc/census-decode-full.mjs --timeout 45      # 45s per server
 *
 * Output: scanner/docs/census-2026/poc/census-decode-full.json
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
const OUT_FILE = path.join(__dirname, "census-decode-full.json");
const CHECKPOINT_INTERVAL = 25; // write output every N completed servers

// ─── CLI Args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let WORKERS = 6;
let TIMEOUT_MS = 30000;
let LIMIT = null;
let FRESH = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--workers" && args[i + 1]) WORKERS = parseInt(args[++i]);
  else if (args[i] === "--timeout" && args[i + 1]) TIMEOUT_MS = parseInt(args[++i]) * 1000;
  else if (args[i] === "--limit" && args[i + 1]) LIMIT = parseInt(args[++i]);
  else if (args[i] === "--fresh") FRESH = true;
  else if (args[i] === "--help" || args[i] === "-h") {
    console.log(`
Full census decode — extended invisible-Unicode classifier

Usage:
  node docs/census-2026/poc/census-decode-full.mjs [options]

Options:
  --workers N    Parallel worker count (default: 6)
  --timeout N    Per-server timeout in seconds (default: 30)
  --limit N      Only scan first N servers (default: all)
  --fresh        Ignore existing output, start from scratch
  --help         Show this help

Output: scanner/docs/census-2026/poc/census-decode-full.json
Resumable: Ctrl+C safe. Re-run to continue from last checkpoint.
`);
    process.exit(0);
  }
}

// ─── Codepoint classification ────────────────────────────────────────────────

// Classes the production scanner ALREADY strips (for cross-validation)
function classifyStripped(cp) {
  if (cp >= 0xe0000 && cp <= 0xe007f) return "tag_block";
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d) return "zero_width";
  if (cp === 0xfeff) return "bom";
  if (cp >= 0xfe00 && cp <= 0xfe0f) return "variation_selector_basic";
  if (cp >= 0x202a && cp <= 0x202e) return "bidi_control";
  if (cp >= 0x2066 && cp <= 0x2069) return "bidi_isolate";
  if (cp === 0x200e || cp === 0x200f) return "lrm_rlm";
  return null;
}

// Classes the production scanner MISSES (the whole point of this script)
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
  // Private Use Area, excluding the tag block range (which is classifyStripped)
  if (cp >= 0xe000 && cp <= 0xf8ff) return "pua_bmp";
  if (cp >= 0xf0000 && cp <= 0xffffd) return "pua_supp_a";
  if (cp >= 0x100000 && cp <= 0x10fffd) return "pua_supp_b";
  return null;
}

function classifyString(s, fieldLabel) {
  if (typeof s !== "string" || s.length === 0) return [];
  const hits = [];
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i);
    if (cp > 0xffff) i++; // surrogate pair, skip the low surrogate
    if (cp < 0x80) continue;
    const stripped = classifyStripped(cp);
    const blind = classifyBlindSpot(cp);
    if (!stripped && !blind) continue;
    hits.push({
      cp,
      cpHex: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
      klass: stripped || blind,
      category: stripped ? "stripped_by_scanner" : "blind_spot",
      field: fieldLabel,
      offset: i,
      context: s.slice(Math.max(0, i - 15), Math.min(s.length, i + 15)),
    });
  }
  return hits;
}

function classifyTool(tool) {
  const allHits = [];
  allHits.push(...classifyString(tool.description, "tool.description"));
  allHits.push(...classifyString(tool.name, "tool.name"));
  const props = tool.inputSchema?.properties || {};
  for (const [pname, pschema] of Object.entries(props)) {
    if (pschema && typeof pschema === "object") {
      allHits.push(...classifyString(pschema.description, `param:${pname}.description`));
      allHits.push(...classifyString(pschema.title, `param:${pname}.title`));
      // Enum values occasionally carry hidden chars
      if (Array.isArray(pschema.enum)) {
        for (const v of pschema.enum) allHits.push(...classifyString(v, `param:${pname}.enum`));
      }
    }
  }
  return allHits;
}

// ─── Build work queue ────────────────────────────────────────────────────────

function loadServersFromReports() {
  const list = JSON.parse(fs.readFileSync(SERVER_LIST, "utf8"));
  // Build multiple lookup indices so we can resolve by id, package, name, or
  // a dash-flattened form that matches the report filename convention.
  const byId = new Map();
  const byPackage = new Map();
  const byName = new Map();
  const byFlat = new Map(); // "npm-@ateam-ai-mcp" → server
  for (const s of list.servers) {
    if (s.id) byId.set(s.id, s);
    if (s.package) byPackage.set(s.package, s);
    if (s.name) byName.set(s.name, s);
    // Flatten id like "npm:@ateam-ai/mcp" → "npm-@ateam-ai-mcp"
    if (s.id) {
      const flat = s.id.replace(":", "-").replace(/\//g, "-");
      byFlat.set(flat, s);
    }
  }

  // Resolver: map a report filename to a server-list entry via a cascade of
  // increasingly fuzzy strategies.
  function resolveReport(file, reportData) {
    const base = file.replace(/\.json$/, "");
    // 1. Exact flat-id match
    if (byFlat.has(base)) return byFlat.get(base);
    // 2. Try report's internal server.name field
    const pkg = reportData.server?.name;
    if (pkg) {
      if (byPackage.has(pkg)) return byPackage.get(pkg);
      if (byName.has(pkg)) return byName.get(pkg);
    }
    // 3. Parse the filename: "npm-@ateam-ai-mcp" → prefix "npm", rest "@ateam-ai-mcp"
    const dashIdx = base.indexOf("-");
    if (dashIdx === -1) return null;
    const prefix = base.slice(0, dashIdx);
    const rest = base.slice(dashIdx + 1);
    // 3a. "npm-@scope-pkg" — reconstruct scoped package forms
    if (rest.startsWith("@")) {
      const parts = rest.slice(1).split("-");
      // Try every split point: @a-b-c → @a/b-c, @a-b/c
      for (let i = 1; i < parts.length; i++) {
        const scope = parts.slice(0, i).join("-");
        const pkgName = parts.slice(i).join("-");
        const candidate = `@${scope}/${pkgName}`;
        const id = `${prefix}:${candidate}`;
        if (byId.has(id)) return byId.get(id);
        if (byPackage.has(candidate)) return byPackage.get(candidate);
      }
    }
    // 3b. "npm-foo-bar" — try as plain package
    const plainId = `${prefix}:${rest}`;
    if (byId.has(plainId)) return byId.get(plainId);
    if (byPackage.has(rest)) return byPackage.get(rest);
    // 4. Fuzzy suffix match (last resort)
    for (const [id, s] of byId) {
      if (id.startsWith(prefix + ":") && id.endsWith(rest.replace(/-/g, "/"))) return s;
    }
    return null;
  }

  const servers = [];
  let unresolved = 0;
  let emptyToolCount = 0;
  const reportFiles = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"));
  for (const file of reportFiles) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
    } catch {
      continue;
    }
    // Skip empty/unknown-toolCount servers — nothing to decode
    if (!data.toolCount || data.toolCount < 1) {
      emptyToolCount++;
      continue;
    }
    const server = resolveReport(file, data);
    if (!server || !server.command) {
      unresolved++;
      continue;
    }
    servers.push({
      reportFile: file,
      reportKey: file.replace(/\.json$/, ""),
      package: server.package,
      name: server.name,
      id: server.id,
      command: server.command,
      runtime: server.runtime,
      expectedToolCount: data.toolCount,
    });
  }
  console.log(`  Reports total: ${reportFiles.length}`);
  console.log(`  Reports with toolCount=0 (skipped): ${emptyToolCount}`);
  console.log(`  Reports unresolved to server-list (skipped): ${unresolved}`);
  return servers;
}

function loadExistingOutput() {
  if (!fs.existsSync(OUT_FILE) || FRESH) return null;
  try {
    return JSON.parse(fs.readFileSync(OUT_FILE, "utf8"));
  } catch {
    return null;
  }
}

// ─── MCP scan worker ─────────────────────────────────────────────────────────

async function scanServer(server) {
  const parts = server.command.split(/\s+/);
  const transport = new StdioClientTransport({
    command: parts[0],
    args: parts.slice(1),
    stderr: "ignore",
  });
  const client = new Client(
    { name: "census-full-decoder", version: "1.0.0" },
    { capabilities: {} }
  );
  const timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`timeout after ${TIMEOUT_MS}ms`)), TIMEOUT_MS)
  );
  try {
    await Promise.race([client.connect(transport), timeoutPromise]);
    const result = await Promise.race([client.listTools(), timeoutPromise]);
    return result.tools || [];
  } finally {
    try {
      await client.close();
    } catch {}
  }
}

// ─── State & checkpointing ───────────────────────────────────────────────────

const state = {
  meta: {
    generatedAt: new Date().toISOString(),
    workers: WORKERS,
    timeoutMs: TIMEOUT_MS,
    scannerVersion: "extended-v1",
  },
  classSummary: { stripped_by_scanner: {}, blind_spot: {} },
  servers: [],
  errors: [],
  donePackages: new Set(),
  counters: { scanned: 0, errors: 0, withHits: 0, withBlindSpotHits: 0 },
};

function mergeExisting(existing) {
  if (!existing) return;
  if (existing.classSummary?.stripped_by_scanner) {
    state.classSummary.stripped_by_scanner = existing.classSummary.stripped_by_scanner;
  }
  if (existing.classSummary?.blind_spot) {
    state.classSummary.blind_spot = existing.classSummary.blind_spot;
  }
  state.servers = existing.servers || [];
  state.errors = existing.errors || [];
  state.counters = existing.counters || state.counters;
  // Rebuild done set
  for (const s of state.servers) state.donePackages.add(s.reportKey);
  for (const e of state.errors) state.donePackages.add(e.reportKey);
}

function writeCheckpoint() {
  const out = {
    meta: state.meta,
    classSummary: state.classSummary,
    counters: state.counters,
    servers: state.servers,
    errors: state.errors,
  };
  fs.writeFileSync(OUT_FILE + ".tmp", JSON.stringify(out, null, 2));
  fs.renameSync(OUT_FILE + ".tmp", OUT_FILE);
}

function recordServerResult(server, tools) {
  const serverEntry = {
    reportKey: server.reportKey,
    package: server.package,
    id: server.id,
    command: server.command,
    runtime: server.runtime,
    expectedToolCount: server.expectedToolCount,
    actualToolCount: tools.length,
    tools: [],
  };
  let serverHasHits = false;
  let serverHasBlindSpot = false;
  for (const tool of tools) {
    const hits = classifyTool(tool);
    if (hits.length === 0) continue;
    serverHasHits = true;
    const classes = {};
    for (const h of hits) {
      classes[h.klass] = (classes[h.klass] || 0) + 1;
      const bucket = h.category === "blind_spot" ? state.classSummary.blind_spot : state.classSummary.stripped_by_scanner;
      bucket[h.klass] = (bucket[h.klass] || 0) + 1;
      if (h.category === "blind_spot") serverHasBlindSpot = true;
    }
    serverEntry.tools.push({
      tool: tool.name,
      hitCount: hits.length,
      classes,
      hits: hits.slice(0, 20), // cap verbosity per tool
    });
  }
  // Only record servers that have hits — the rest would bloat the file
  if (serverHasHits) {
    state.servers.push(serverEntry);
    state.counters.withHits++;
    if (serverHasBlindSpot) state.counters.withBlindSpotHits++;
  }
  state.counters.scanned++;
  state.donePackages.add(server.reportKey);
}

function recordError(server, err) {
  state.errors.push({
    reportKey: server.reportKey,
    package: server.package,
    command: server.command,
    error: String(err.message || err).slice(0, 300),
  });
  state.counters.errors++;
  state.donePackages.add(server.reportKey);
}

// ─── Worker pool ─────────────────────────────────────────────────────────────

async function runWorkerPool(queue) {
  let cursor = 0;
  const total = queue.length;
  const startTime = Date.now();
  let sinceCheckpoint = 0;

  async function worker(id) {
    while (true) {
      const index = cursor++;
      if (index >= queue.length) return;
      const server = queue[index];
      try {
        const tools = await scanServer(server);
        recordServerResult(server, tools);
      } catch (e) {
        recordError(server, e);
      }
      sinceCheckpoint++;
      const done = state.counters.scanned + state.counters.errors;
      if (sinceCheckpoint >= CHECKPOINT_INTERVAL) {
        writeCheckpoint();
        sinceCheckpoint = 0;
        const elapsed = (Date.now() - startTime) / 1000;
        const rate = done / elapsed;
        const remaining = total - done;
        const eta = remaining / Math.max(rate, 0.01);
        const etaMin = Math.round(eta / 60);
        console.log(
          `  [${done}/${total + state.donePackages.size - queue.length}] ` +
          `scanned=${state.counters.scanned} errors=${state.counters.errors} ` +
          `withHits=${state.counters.withHits} blindSpot=${state.counters.withBlindSpotHits} ` +
          `| ${rate.toFixed(1)}/s ETA ~${etaMin}m`
        );
      }
    }
  }

  const workers = [];
  for (let i = 0; i < WORKERS; i++) workers.push(worker(i));
  await Promise.all(workers);
  writeCheckpoint();
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n  AgentSID Paper 5 — Full Census Decode (Extended Classifier)");
  console.log(`  Started: ${new Date().toISOString()}`);
  console.log(`  Workers: ${WORKERS} | Timeout: ${TIMEOUT_MS / 1000}s/server`);
  console.log();

  const existing = loadExistingOutput();
  if (existing) {
    mergeExisting(existing);
    console.log(`  Resuming from existing output`);
    console.log(`    Previously scanned: ${state.counters.scanned}`);
    console.log(`    Previously errored: ${state.counters.errors}`);
    console.log(`    Servers with hits so far: ${state.counters.withHits}`);
    console.log(`    Servers with blind-spot hits so far: ${state.counters.withBlindSpotHits}`);
  } else {
    console.log(`  Starting fresh scan`);
  }

  const allServers = loadServersFromReports();
  console.log(`\n  Eligible servers from reports/: ${allServers.length}`);

  let queue = allServers.filter((s) => !state.donePackages.has(s.reportKey));
  if (LIMIT) queue = queue.slice(0, LIMIT);
  console.log(`  Queue size (new/remaining): ${queue.length}\n`);

  if (queue.length === 0) {
    console.log("  Nothing to do. Use --fresh to re-scan from scratch.");
    printFinalSummary();
    return;
  }

  // Graceful shutdown
  let interrupted = false;
  process.on("SIGINT", () => {
    if (interrupted) process.exit(130);
    interrupted = true;
    console.log("\n\n  Caught SIGINT — writing checkpoint and exiting gracefully...");
    writeCheckpoint();
    console.log("  Checkpoint saved. Re-run to resume.");
    process.exit(0);
  });

  await runWorkerPool(queue);

  console.log("\n  ═══ Scan Complete ═══");
  printFinalSummary();
}

function printFinalSummary() {
  console.log(`\n  Scanned servers (success): ${state.counters.scanned}`);
  console.log(`  Errored servers: ${state.counters.errors}`);
  console.log(`  Servers with any hidden codepoints: ${state.counters.withHits}`);
  console.log(`  Servers with BLIND-SPOT codepoints: ${state.counters.withBlindSpotHits}`);

  console.log(`\n  Stripped-class distribution (cross-validation with scanner):`);
  const strippedSorted = Object.entries(state.classSummary.stripped_by_scanner).sort((a, b) => b[1] - a[1]);
  if (strippedSorted.length === 0) console.log("    (none)");
  for (const [k, v] of strippedSorted) console.log(`    ${k.padEnd(36)} ${v}`);

  console.log(`\n  BLIND-SPOT class distribution (scanner misses these):`);
  const blindSorted = Object.entries(state.classSummary.blind_spot).sort((a, b) => b[1] - a[1]);
  if (blindSorted.length === 0) console.log("    (none — scanner's sanitizer covers the full invisible-Unicode space in practice)");
  for (const [k, v] of blindSorted) console.log(`    ${k.padEnd(36)} ${v}`);

  console.log(`\n  Output: ${OUT_FILE}`);
  console.log(`  Finished: ${new Date().toISOString()}\n`);
}

main().catch((e) => {
  console.error("\n  FATAL:", e);
  writeCheckpoint();
  process.exit(1);
});
