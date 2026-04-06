#!/usr/bin/env node
/**
 * Full census decode v2 — expanded field coverage.
 *
 * v1 (census-decode-full.mjs) scanned:
 *   - tool.description
 *   - tool.name
 *   - param.description, param.title
 *   - param.enum values
 *
 * v2 adds:
 *   - server.description (top-level server metadata from initialize)
 *   - prompts/list: prompt.name, prompt.description, argument descriptions
 *   - resources/list: resource.name, resource.description, resource.mimeType
 *   - resourceTemplates/list: same fields
 *   - Schema fields: title, const (stringified), pattern, format, default (if string), examples
 *   - Schema nested object properties (recursive)
 *   - Tool annotations/metadata if present
 *
 * Everything else is identical to v1: same 22-class classifier, same worker pool,
 * same resumable checkpointing, same output schema shape.
 *
 * Usage:
 *   node docs/census-2026/poc/census-decode-v2.mjs
 *   node docs/census-2026/poc/census-decode-v2.mjs --workers 8
 *   node docs/census-2026/poc/census-decode-v2.mjs --fresh
 *
 * Output: scanner/docs/census-2026/poc/census-decode-v2.json
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
const OUT_FILE = path.join(__dirname, "census-decode-v2.json");
const CHECKPOINT_INTERVAL = 25;

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
    console.log(`census-decode-v2 — expanded-field invisible-Unicode decoder
Options: --workers N | --timeout N (seconds) | --limit N | --fresh`);
    process.exit(0);
  }
}

// ─── Codepoint classification (identical to v1) ──────────────────────────────

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

function classifyString(s, field, objectType) {
  if (typeof s !== "string" || s.length === 0) return [];
  const hits = [];
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i);
    if (cp > 0xffff) i++;
    if (cp < 0x80) continue;
    const stripped = classifyStripped(cp);
    const blind = classifyBlindSpot(cp);
    if (!stripped && !blind) continue;
    hits.push({
      cp,
      cpHex: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
      klass: stripped || blind,
      category: stripped ? "stripped_by_scanner" : "blind_spot",
      field,
      objectType,
      offset: i,
      context: s.slice(Math.max(0, i - 15), Math.min(s.length, i + 15)),
    });
  }
  return hits;
}

// ─── Schema walker: recurse into nested properties, collect every string ─────

function walkSchema(schema, prefix, hits, objectType) {
  if (!schema || typeof schema !== "object") return;
  // Scalar string fields on this schema node
  for (const key of ["title", "description", "format", "pattern"]) {
    if (typeof schema[key] === "string") {
      hits.push(...classifyString(schema[key], `${prefix}.${key}`, objectType));
    }
  }
  // const / default / examples — may be any type; stringify if string-ish
  if (typeof schema.const === "string") {
    hits.push(...classifyString(schema.const, `${prefix}.const`, objectType));
  }
  if (typeof schema.default === "string") {
    hits.push(...classifyString(schema.default, `${prefix}.default`, objectType));
  }
  if (Array.isArray(schema.examples)) {
    for (const [ei, ex] of schema.examples.entries()) {
      if (typeof ex === "string") {
        hits.push(...classifyString(ex, `${prefix}.examples[${ei}]`, objectType));
      }
    }
  }
  if (Array.isArray(schema.enum)) {
    for (const [ei, v] of schema.enum.entries()) {
      if (typeof v === "string") {
        hits.push(...classifyString(v, `${prefix}.enum[${ei}]`, objectType));
      }
    }
  }
  // Recurse: properties, items, additionalProperties, patternProperties, oneOf/anyOf/allOf
  if (schema.properties && typeof schema.properties === "object") {
    for (const [k, v] of Object.entries(schema.properties)) {
      walkSchema(v, `${prefix}.properties.${k}`, hits, objectType);
    }
  }
  if (schema.patternProperties && typeof schema.patternProperties === "object") {
    for (const [k, v] of Object.entries(schema.patternProperties)) {
      walkSchema(v, `${prefix}.patternProperties.${k}`, hits, objectType);
    }
  }
  if (schema.items) {
    if (Array.isArray(schema.items)) {
      schema.items.forEach((it, idx) => walkSchema(it, `${prefix}.items[${idx}]`, hits, objectType));
    } else {
      walkSchema(schema.items, `${prefix}.items`, hits, objectType);
    }
  }
  if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
    walkSchema(schema.additionalProperties, `${prefix}.additionalProperties`, hits, objectType);
  }
  for (const combo of ["oneOf", "anyOf", "allOf"]) {
    if (Array.isArray(schema[combo])) {
      schema[combo].forEach((s, idx) => walkSchema(s, `${prefix}.${combo}[${idx}]`, hits, objectType));
    }
  }
}

// ─── Classify tool, prompt, resource ─────────────────────────────────────────

function classifyTool(tool) {
  const hits = [];
  hits.push(...classifyString(tool.name, "tool.name", "tool"));
  hits.push(...classifyString(tool.description, "tool.description", "tool"));
  hits.push(...classifyString(tool.title, "tool.title", "tool"));
  if (tool.inputSchema) walkSchema(tool.inputSchema, "tool.inputSchema", hits, "tool");
  if (tool.outputSchema) walkSchema(tool.outputSchema, "tool.outputSchema", hits, "tool");
  if (tool.annotations && typeof tool.annotations === "object") {
    for (const [k, v] of Object.entries(tool.annotations)) {
      if (typeof v === "string") hits.push(...classifyString(v, `tool.annotations.${k}`, "tool"));
    }
  }
  return hits;
}

function classifyPrompt(prompt) {
  const hits = [];
  hits.push(...classifyString(prompt.name, "prompt.name", "prompt"));
  hits.push(...classifyString(prompt.description, "prompt.description", "prompt"));
  if (Array.isArray(prompt.arguments)) {
    for (const [ai, arg] of prompt.arguments.entries()) {
      hits.push(...classifyString(arg.name, `prompt.arguments[${ai}].name`, "prompt"));
      hits.push(...classifyString(arg.description, `prompt.arguments[${ai}].description`, "prompt"));
    }
  }
  return hits;
}

function classifyResource(resource, type = "resource") {
  const hits = [];
  hits.push(...classifyString(resource.name, `${type}.name`, type));
  hits.push(...classifyString(resource.description, `${type}.description`, type));
  hits.push(...classifyString(resource.title, `${type}.title`, type));
  hits.push(...classifyString(resource.uri, `${type}.uri`, type));
  hits.push(...classifyString(resource.uriTemplate, `${type}.uriTemplate`, type));
  hits.push(...classifyString(resource.mimeType, `${type}.mimeType`, type));
  return hits;
}

function classifyServerInfo(serverInfo) {
  const hits = [];
  if (!serverInfo) return hits;
  hits.push(...classifyString(serverInfo.name, "server.name", "server"));
  hits.push(...classifyString(serverInfo.title, "server.title", "server"));
  hits.push(...classifyString(serverInfo.description, "server.description", "server"));
  hits.push(...classifyString(serverInfo.version, "server.version", "server"));
  if (serverInfo.instructions) {
    hits.push(...classifyString(serverInfo.instructions, "server.instructions", "server"));
  }
  return hits;
}

// ─── Server list resolver (same as v1) ───────────────────────────────────────

function loadServersFromReports() {
  const list = JSON.parse(fs.readFileSync(SERVER_LIST, "utf8"));
  const byId = new Map();
  const byPackage = new Map();
  const byName = new Map();
  const byFlat = new Map();
  for (const s of list.servers) {
    if (s.id) byId.set(s.id, s);
    if (s.package) byPackage.set(s.package, s);
    if (s.name) byName.set(s.name, s);
    if (s.id) byFlat.set(s.id.replace(":", "-").replace(/\//g, "-"), s);
  }

  function resolveReport(file, reportData) {
    const base = file.replace(/\.json$/, "");
    if (byFlat.has(base)) return byFlat.get(base);
    const pkg = reportData.server?.name;
    if (pkg) {
      if (byPackage.has(pkg)) return byPackage.get(pkg);
      if (byName.has(pkg)) return byName.get(pkg);
    }
    const dashIdx = base.indexOf("-");
    if (dashIdx === -1) return null;
    const prefix = base.slice(0, dashIdx);
    const rest = base.slice(dashIdx + 1);
    if (rest.startsWith("@")) {
      const parts = rest.slice(1).split("-");
      for (let i = 1; i < parts.length; i++) {
        const scope = parts.slice(0, i).join("-");
        const pkgName = parts.slice(i).join("-");
        const candidate = `@${scope}/${pkgName}`;
        const id = `${prefix}:${candidate}`;
        if (byId.has(id)) return byId.get(id);
        if (byPackage.has(candidate)) return byPackage.get(candidate);
      }
    }
    const plainId = `${prefix}:${rest}`;
    if (byId.has(plainId)) return byId.get(plainId);
    if (byPackage.has(rest)) return byPackage.get(rest);
    return null;
  }

  const servers = [];
  let emptyToolCount = 0;
  let unresolved = 0;
  const reportFiles = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"));
  for (const file of reportFiles) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
    } catch {
      continue;
    }
    // v2: include servers even if toolCount=0, because they might have prompts or resources
    // BUT prioritize the ones with tools — stub packages with no tools and no anything are
    // uninteresting. Be explicit: include if toolCount >= 1 OR the package is known to ship
    // prompts/resources (we can't tell from the report, so include anything with toolCount >= 1
    // matching v1 behavior, then the scan itself will also pull prompts/resources).
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

// ─── MCP scan: tools + prompts + resources + serverInfo ──────────────────────

async function scanServer(server) {
  const parts = server.command.split(/\s+/);
  const transport = new StdioClientTransport({
    command: parts[0],
    args: parts.slice(1),
    stderr: "ignore",
  });
  const client = new Client(
    { name: "census-v2-decoder", version: "2.0.0" },
    { capabilities: {} }
  );
  const timeout = (ms, label) =>
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timeout`)), ms));

  try {
    await Promise.race([client.connect(transport), timeout(TIMEOUT_MS, "connect")]);

    // serverInfo comes from initialize — the SDK stores it on the client
    const serverInfo = client.getServerVersion?.() || client.serverInfo || null;

    // tools/list
    let tools = [];
    try {
      const r = await Promise.race([client.listTools(), timeout(TIMEOUT_MS, "tools/list")]);
      tools = r.tools || [];
    } catch {}

    // prompts/list (may not be supported)
    let prompts = [];
    try {
      const r = await Promise.race([client.listPrompts(), timeout(TIMEOUT_MS, "prompts/list")]);
      prompts = r.prompts || [];
    } catch {}

    // resources/list (may not be supported)
    let resources = [];
    try {
      const r = await Promise.race([client.listResources(), timeout(TIMEOUT_MS, "resources/list")]);
      resources = r.resources || [];
    } catch {}

    // resources/templates/list
    let resourceTemplates = [];
    try {
      const r = await Promise.race([
        client.listResourceTemplates(),
        timeout(TIMEOUT_MS, "resourceTemplates/list"),
      ]);
      resourceTemplates = r.resourceTemplates || [];
    } catch {}

    return { serverInfo, tools, prompts, resources, resourceTemplates };
  } finally {
    try {
      await client.close();
    } catch {}
  }
}

// ─── State ───────────────────────────────────────────────────────────────────

const state = {
  meta: {
    generatedAt: new Date().toISOString(),
    workers: WORKERS,
    timeoutMs: TIMEOUT_MS,
    scannerVersion: "v2-expanded-fields",
    fieldCoverage: [
      "tool.name", "tool.description", "tool.title",
      "tool.inputSchema (recursive: properties, items, titles, const, default, pattern, format, examples, enum)",
      "tool.outputSchema (recursive)",
      "tool.annotations",
      "prompt.name", "prompt.description", "prompt.arguments[].name/description",
      "resource.name/description/title/uri/uriTemplate/mimeType",
      "resourceTemplate.name/description/title/uri/uriTemplate/mimeType",
      "server.name/title/description/version/instructions",
    ],
  },
  classSummary: { stripped_by_scanner: {}, blind_spot: {} },
  fieldSummary: {}, // field -> count (across all classes)
  objectTypeSummary: {}, // tool/prompt/resource/server -> count
  servers: [],
  errors: [],
  donePackages: new Set(),
  counters: {
    scanned: 0,
    errors: 0,
    withHits: 0,
    withBlindSpotHits: 0,
    withPrompts: 0,
    withResources: 0,
    withResourceTemplates: 0,
  },
};

function mergeExisting(existing) {
  if (!existing) return;
  if (existing.classSummary?.stripped_by_scanner) state.classSummary.stripped_by_scanner = existing.classSummary.stripped_by_scanner;
  if (existing.classSummary?.blind_spot) state.classSummary.blind_spot = existing.classSummary.blind_spot;
  if (existing.fieldSummary) state.fieldSummary = existing.fieldSummary;
  if (existing.objectTypeSummary) state.objectTypeSummary = existing.objectTypeSummary;
  state.servers = existing.servers || [];
  state.errors = existing.errors || [];
  state.counters = { ...state.counters, ...(existing.counters || {}) };
  for (const s of state.servers) state.donePackages.add(s.reportKey);
  for (const e of state.errors) state.donePackages.add(e.reportKey);
}

function writeCheckpoint() {
  const out = {
    meta: state.meta,
    classSummary: state.classSummary,
    fieldSummary: state.fieldSummary,
    objectTypeSummary: state.objectTypeSummary,
    counters: state.counters,
    servers: state.servers,
    errors: state.errors,
  };
  fs.writeFileSync(OUT_FILE + ".tmp", JSON.stringify(out, null, 2));
  fs.renameSync(OUT_FILE + ".tmp", OUT_FILE);
}

function recordServerResult(server, manifest) {
  const { serverInfo, tools, prompts, resources, resourceTemplates } = manifest;
  const allHits = [];

  allHits.push(...classifyServerInfo(serverInfo));
  for (const tool of tools) allHits.push(...classifyTool(tool));
  for (const prompt of prompts) allHits.push(...classifyPrompt(prompt));
  for (const resource of resources) allHits.push(...classifyResource(resource, "resource"));
  for (const rt of resourceTemplates) allHits.push(...classifyResource(rt, "resourceTemplate"));

  if (prompts.length > 0) state.counters.withPrompts++;
  if (resources.length > 0) state.counters.withResources++;
  if (resourceTemplates.length > 0) state.counters.withResourceTemplates++;

  if (allHits.length > 0) {
    const serverEntry = {
      reportKey: server.reportKey,
      package: server.package,
      id: server.id,
      command: server.command,
      runtime: server.runtime,
      toolCount: tools.length,
      promptCount: prompts.length,
      resourceCount: resources.length,
      resourceTemplateCount: resourceTemplates.length,
      hits: allHits.slice(0, 200), // cap per server
    };
    state.servers.push(serverEntry);
    state.counters.withHits++;

    let hasBlindSpot = false;
    for (const h of allHits) {
      const bucket = h.category === "blind_spot" ? state.classSummary.blind_spot : state.classSummary.stripped_by_scanner;
      bucket[h.klass] = (bucket[h.klass] || 0) + 1;
      state.fieldSummary[h.field] = (state.fieldSummary[h.field] || 0) + 1;
      state.objectTypeSummary[h.objectType] = (state.objectTypeSummary[h.objectType] || 0) + 1;
      if (h.category === "blind_spot") hasBlindSpot = true;
    }
    if (hasBlindSpot) state.counters.withBlindSpotHits++;
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
        const manifest = await scanServer(server);
        recordServerResult(server, manifest);
      } catch (e) {
        recordError(server, e);
      }
      sinceCheckpoint++;
      if (sinceCheckpoint >= CHECKPOINT_INTERVAL) {
        writeCheckpoint();
        sinceCheckpoint = 0;
        const done = state.counters.scanned + state.counters.errors;
        const elapsed = (Date.now() - startTime) / 1000;
        const rate = done / elapsed;
        const remaining = total - (done - (state.donePackages.size - queue.length));
        const eta = Math.max(0, remaining) / Math.max(rate, 0.01);
        console.log(
          `  [${done} done] scanned=${state.counters.scanned} err=${state.counters.errors} ` +
          `hits=${state.counters.withHits} blind=${state.counters.withBlindSpotHits} ` +
          `prompts=${state.counters.withPrompts} res=${state.counters.withResources} ` +
          `| ${rate.toFixed(1)}/s ETA ~${Math.round(eta / 60)}m`
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
  console.log("\n  AgentSID Paper 5 — Census Decode v2 (Expanded Field Coverage)");
  console.log(`  Started: ${new Date().toISOString()}`);
  console.log(`  Workers: ${WORKERS} | Timeout: ${TIMEOUT_MS / 1000}s/server`);
  console.log(`  Fields: tool + prompt + resource + resourceTemplate + serverInfo + full schema recursion\n`);

  const existing = loadExistingOutput();
  if (existing) {
    mergeExisting(existing);
    console.log(`  Resuming from checkpoint`);
    console.log(`    Previously scanned: ${state.counters.scanned}`);
    console.log(`    Previously errored: ${state.counters.errors}`);
    console.log(`    Servers with hits: ${state.counters.withHits}`);
    console.log(`    Servers with blind-spot hits: ${state.counters.withBlindSpotHits}`);
  }

  const allServers = loadServersFromReports();
  console.log(`\n  Eligible servers: ${allServers.length}`);

  let queue = allServers.filter((s) => !state.donePackages.has(s.reportKey));
  if (LIMIT) queue = queue.slice(0, LIMIT);
  console.log(`  Queue (new/remaining): ${queue.length}\n`);

  if (queue.length === 0) {
    console.log("  Nothing to do. Use --fresh to re-scan from scratch.");
    printFinalSummary();
    return;
  }

  let interrupted = false;
  process.on("SIGINT", () => {
    if (interrupted) process.exit(130);
    interrupted = true;
    console.log("\n\n  Caught SIGINT — writing checkpoint...");
    writeCheckpoint();
    console.log("  Saved. Re-run to resume.");
    process.exit(0);
  });

  await runWorkerPool(queue);

  console.log("\n  ═══ v2 Scan Complete ═══");
  printFinalSummary();
}

function printFinalSummary() {
  console.log(`\n  Scanned: ${state.counters.scanned}`);
  console.log(`  Errored: ${state.counters.errors}`);
  console.log(`  Servers with any hidden codepoints: ${state.counters.withHits}`);
  console.log(`  Servers with BLIND-SPOT codepoints: ${state.counters.withBlindSpotHits}`);
  console.log(`  Servers exposing prompts/list: ${state.counters.withPrompts}`);
  console.log(`  Servers exposing resources/list: ${state.counters.withResources}`);
  console.log(`  Servers exposing resourceTemplates: ${state.counters.withResourceTemplates}`);

  console.log(`\n  Stripped-class distribution:`);
  const strippedSorted = Object.entries(state.classSummary.stripped_by_scanner).sort((a, b) => b[1] - a[1]);
  if (strippedSorted.length === 0) console.log("    (none)");
  for (const [k, v] of strippedSorted) console.log(`    ${k.padEnd(36)} ${v}`);

  console.log(`\n  BLIND-SPOT class distribution:`);
  const blindSorted = Object.entries(state.classSummary.blind_spot).sort((a, b) => b[1] - a[1]);
  if (blindSorted.length === 0) console.log("    (none)");
  for (const [k, v] of blindSorted) console.log(`    ${k.padEnd(36)} ${v}`);

  console.log(`\n  Object-type distribution:`);
  for (const [k, v] of Object.entries(state.objectTypeSummary).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${k.padEnd(20)} ${v}`);
  }

  console.log(`\n  Field distribution (top 15):`);
  const fieldSorted = Object.entries(state.fieldSummary).sort((a, b) => b[1] - a[1]).slice(0, 15);
  for (const [k, v] of fieldSorted) console.log(`    ${k.padEnd(50)} ${v}`);

  console.log(`\n  Output: ${OUT_FILE}`);
  console.log(`  Finished: ${new Date().toISOString()}\n`);
}

main().catch((e) => {
  console.error("\n  FATAL:", e);
  writeCheckpoint();
  process.exit(1);
});
