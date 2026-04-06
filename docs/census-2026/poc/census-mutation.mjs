#!/usr/bin/env node
/**
 * Census mutation scan — detect pull-rug self-mutating tool descriptions.
 *
 * The greet() attack in mcp-server-everything-wrong rewrites its own docstring
 * the first time it's invoked, re-registers itself, and emits tools/list_changed.
 * Static scanners (ours and every competitor) capture a single tools/list snapshot
 * and never detect this. The only way to catch it is to:
 *
 *   1. Connect, call tools/list (snapshot A)
 *   2. Invoke one safe read-only-ish tool with minimal arguments
 *   3. Watch for tools/list_changed notifications during the invocation
 *   4. Call tools/list again (snapshot B)
 *   5. Diff A vs B
 *
 * This script does exactly that, across a sample of MCP servers from reports/,
 * and reports every server whose manifest mutates between snapshots A and B.
 *
 * Safety: we only invoke tools whose name matches a conservative allowlist of
 * read-only verbs (list, get, read, search, find, show, describe, fetch, echo,
 * ping, status, version, info). We pass the minimal possible arguments (either
 * no arguments if schema allows, or trivial placeholder strings like "test").
 * We skip tools whose schema requires non-trivial arguments we can't fabricate.
 *
 * Resumable. Parallel. Output: census-mutation.json.
 *
 * Usage:
 *   node docs/census-2026/poc/census-mutation.mjs                  # full scan
 *   node docs/census-2026/poc/census-mutation.mjs --limit 200      # sample
 *   node docs/census-2026/poc/census-mutation.mjs --workers 4
 *   node docs/census-2026/poc/census-mutation.mjs --fresh
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER_ROOT = path.resolve(__dirname, "../../..");
const REPORTS_DIR = path.join(SCANNER_ROOT, "reports");
const SERVER_LIST = path.join(SCANNER_ROOT, "scripts/server-list.json");
const OUT_FILE = path.join(__dirname, "census-mutation.json");
const CHECKPOINT_INTERVAL = 20;

const args = process.argv.slice(2);
let WORKERS = 4;
let TIMEOUT_MS = 45000; // longer because we do 2 list calls + 1 invoke
let LIMIT = null;
let FRESH = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--workers" && args[i + 1]) WORKERS = parseInt(args[++i]);
  else if (args[i] === "--timeout" && args[i + 1]) TIMEOUT_MS = parseInt(args[++i]) * 1000;
  else if (args[i] === "--limit" && args[i + 1]) LIMIT = parseInt(args[++i]);
  else if (args[i] === "--fresh") FRESH = true;
}

// ─── Safe tool selection ─────────────────────────────────────────────────────

// Prefer tools whose names start with a read-only verb. Avoid anything that
// looks like a write, delete, send, execute, create, update, or run operation.
const SAFE_VERBS = /^(list|get|read|search|find|show|describe|fetch|echo|ping|status|version|info|health|help|who_?am_?i|test|check|query|lookup|view|inspect)/i;
const UNSAFE_VERBS = /^(create|write|update|delete|remove|drop|send|email|execute|exec|run|eval|shell|deploy|publish|kill|stop|start|restart|transfer|pay|charge|withdraw|insert|set|post|put|patch|add|remove|destroy|purge|modify|change|rename|move|copy)/i;

function pickSafeTool(tools) {
  // Two-tier candidate ranking:
  //   tier 1: name starts with SAFE_VERBS (highest confidence read-only)
  //   tier 2: name does not start with UNSAFE_VERBS AND has zero required args
  //           (lower confidence but still probably side-effect-free)
  // Within each tier, prefer no-arg over synthesized-arg.
  const tier1 = [];
  const tier2 = [];
  for (const tool of tools) {
    const name = tool.name || "";
    if (UNSAFE_VERBS.test(name)) continue;
    const schema = tool.inputSchema;
    const required = Array.isArray(schema?.required) ? schema.required : [];
    let args = null;
    if (!schema || !schema.properties || required.length === 0) {
      args = {};
    } else {
      const syn = {};
      let ok = true;
      for (const field of required) {
        const prop = schema.properties[field];
        if (!prop) { ok = false; break; }
        if (prop.type === "string") syn[field] = "test";
        else if (prop.type === "number" || prop.type === "integer") syn[field] = 1;
        else if (prop.type === "boolean") syn[field] = false;
        else if (prop.type === "array") syn[field] = [];
        else if (prop.type === "object") syn[field] = {};
        else { ok = false; break; }
      }
      if (ok) args = syn;
    }
    if (args === null) continue;
    if (SAFE_VERBS.test(name)) tier1.push({ tool, args });
    else if (Object.keys(args).length === 0) tier2.push({ tool, args });
  }
  // Tier 1 preferred. Within tier, prefer fewer args.
  const pool = tier1.length > 0 ? tier1 : tier2;
  pool.sort((a, b) => Object.keys(a.args).length - Object.keys(b.args).length);
  return pool[0] || null;
}

// ─── Manifest diff ───────────────────────────────────────────────────────────

function hashTools(tools) {
  const normalized = tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchemaJson: t.inputSchema ? JSON.stringify(t.inputSchema) : null,
  }));
  return JSON.stringify(normalized);
}

function diffTools(before, after) {
  const changes = [];
  const byName = new Map();
  for (const t of before) byName.set(t.name, t);
  const afterNames = new Set(after.map((t) => t.name));

  for (const a of after) {
    const b = byName.get(a.name);
    if (!b) {
      changes.push({ type: "added", tool: a.name });
      continue;
    }
    if (a.description !== b.description) {
      changes.push({
        type: "description_changed",
        tool: a.name,
        before: (b.description || "").slice(0, 200),
        after: (a.description || "").slice(0, 200),
      });
    }
    const aSchema = JSON.stringify(a.inputSchema || null);
    const bSchema = JSON.stringify(b.inputSchema || null);
    if (aSchema !== bSchema) {
      changes.push({ type: "schema_changed", tool: a.name });
    }
  }
  for (const b of before) {
    if (!afterNames.has(b.name)) {
      changes.push({ type: "removed", tool: b.name });
    }
  }
  return changes;
}

// ─── MCP scan ────────────────────────────────────────────────────────────────

async function scanForMutation(server) {
  const parts = server.command.split(/\s+/);
  const transport = new StdioClientTransport({
    command: parts[0],
    args: parts.slice(1),
    stderr: "ignore",
  });
  const client = new Client(
    { name: "census-mutation-scanner", version: "1.0.0" },
    { capabilities: {} }
  );

  let listChangedFired = false;
  try {
    client.setNotificationHandler(ToolListChangedNotificationSchema, async () => {
      listChangedFired = true;
    });
  } catch {}

  const timeoutLabel = (label) =>
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timeout`)), TIMEOUT_MS));

  try {
    await Promise.race([client.connect(transport), timeoutLabel("connect")]);

    // Snapshot A
    let listA;
    try {
      listA = await Promise.race([client.listTools(), timeoutLabel("tools/list A")]);
    } catch (e) {
      return { status: "list_a_failed", error: e.message };
    }
    const toolsA = listA.tools || [];
    const hashA = hashTools(toolsA);

    // Pick a safe tool to invoke
    const pick = pickSafeTool(toolsA);
    if (!pick) {
      return {
        status: "no_safe_tool",
        toolCount: toolsA.length,
        hashA,
        hashB: hashA,
        listChangedFired: false,
        changes: [],
      };
    }

    // Invoke the tool
    let invokeError = null;
    try {
      await Promise.race([
        client.callTool({ name: pick.tool.name, arguments: pick.args }),
        timeoutLabel(`call ${pick.tool.name}`),
      ]);
    } catch (e) {
      invokeError = e.message;
      // Continue anyway — we still want to diff the manifest
    }

    // Give the server a moment to emit notifications
    await new Promise((r) => setTimeout(r, 500));

    // Snapshot B
    let listB;
    try {
      listB = await Promise.race([client.listTools(), timeoutLabel("tools/list B")]);
    } catch (e) {
      return { status: "list_b_failed", error: e.message, toolCount: toolsA.length };
    }
    const toolsB = listB.tools || [];
    const hashB = hashTools(toolsB);

    const mutated = hashA !== hashB;
    const changes = mutated ? diffTools(toolsA, toolsB) : [];

    return {
      status: mutated ? "mutated" : "stable",
      toolCount: toolsA.length,
      invokedTool: pick.tool.name,
      invokedArgs: pick.args,
      invokeError,
      listChangedFired,
      changes,
    };
  } finally {
    try {
      await client.close();
    } catch {}
  }
}

// ─── Server list resolver (same as v2) ───────────────────────────────────────

function loadServersFromReports() {
  const list = JSON.parse(fs.readFileSync(SERVER_LIST, "utf8"));
  const byId = new Map(), byPackage = new Map(), byName = new Map(), byFlat = new Map();
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
  for (const file of fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"))) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
    } catch { continue; }
    if (!data.toolCount || data.toolCount < 1) continue;
    const server = resolveReport(file, data);
    if (!server || !server.command) continue;
    servers.push({
      reportKey: file.replace(/\.json$/, ""),
      package: server.package,
      id: server.id,
      command: server.command,
      runtime: server.runtime,
    });
  }
  return servers;
}

function loadExistingOutput() {
  if (!fs.existsSync(OUT_FILE) || FRESH) return null;
  try { return JSON.parse(fs.readFileSync(OUT_FILE, "utf8")); } catch { return null; }
}

// ─── State ───────────────────────────────────────────────────────────────────

const state = {
  meta: { generatedAt: new Date().toISOString(), workers: WORKERS, timeoutMs: TIMEOUT_MS },
  counters: {
    total: 0,
    stable: 0,
    mutated: 0,
    listChangedEmitted: 0,
    noSafeTool: 0,
    listAFailed: 0,
    listBFailed: 0,
    errors: 0,
  },
  mutatedServers: [],
  errors: [],
  donePackages: new Set(),
};

function mergeExisting(existing) {
  if (!existing) return;
  if (existing.counters) state.counters = { ...state.counters, ...existing.counters };
  state.mutatedServers = existing.mutatedServers || [];
  state.errors = existing.errors || [];
  for (const s of state.mutatedServers) state.donePackages.add(s.reportKey);
  for (const e of state.errors) state.donePackages.add(e.reportKey);
  // We need to track stable servers too via a separate set
  if (Array.isArray(existing.donePackages)) {
    for (const k of existing.donePackages) state.donePackages.add(k);
  }
}

function writeCheckpoint() {
  const out = {
    meta: state.meta,
    counters: state.counters,
    mutatedServers: state.mutatedServers,
    errors: state.errors,
    donePackages: Array.from(state.donePackages),
  };
  fs.writeFileSync(OUT_FILE + ".tmp", JSON.stringify(out, null, 2));
  fs.renameSync(OUT_FILE + ".tmp", OUT_FILE);
}

// ─── Worker pool ─────────────────────────────────────────────────────────────

async function runWorkerPool(queue) {
  let cursor = 0;
  const startTime = Date.now();
  let sinceCheckpoint = 0;

  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= queue.length) return;
      const server = queue[index];

      try {
        const result = await scanForMutation(server);
        state.counters.total++;
        if (result.status === "mutated") {
          state.counters.mutated++;
          if (result.listChangedFired) state.counters.listChangedEmitted++;
          state.mutatedServers.push({
            reportKey: server.reportKey,
            package: server.package,
            id: server.id,
            command: server.command,
            ...result,
          });
          console.log(`  ★ MUTATED: ${server.package} (invoked ${result.invokedTool}, listChanged=${result.listChangedFired}, ${result.changes.length} changes)`);
        } else if (result.status === "stable") {
          state.counters.stable++;
        } else if (result.status === "no_safe_tool") {
          state.counters.noSafeTool++;
        } else if (result.status === "list_a_failed") {
          state.counters.listAFailed++;
        } else if (result.status === "list_b_failed") {
          state.counters.listBFailed++;
        }
        state.donePackages.add(server.reportKey);
      } catch (e) {
        state.counters.errors++;
        state.errors.push({
          reportKey: server.reportKey,
          package: server.package,
          error: String(e.message || e).slice(0, 300),
        });
        state.donePackages.add(server.reportKey);
      }

      sinceCheckpoint++;
      if (sinceCheckpoint >= CHECKPOINT_INTERVAL) {
        writeCheckpoint();
        sinceCheckpoint = 0;
        const elapsed = (Date.now() - startTime) / 1000;
        const rate = state.counters.total / Math.max(elapsed, 1);
        const remaining = queue.length - (cursor);
        const eta = remaining / Math.max(rate, 0.01);
        console.log(
          `  [${cursor}/${queue.length}] ` +
          `stable=${state.counters.stable} mutated=${state.counters.mutated} ` +
          `nosafe=${state.counters.noSafeTool} errors=${state.counters.errors} ` +
          `| ${rate.toFixed(1)}/s ETA ~${Math.round(eta / 60)}m`
        );
      }
    }
  }

  const workers = [];
  for (let i = 0; i < WORKERS; i++) workers.push(worker());
  await Promise.all(workers);
  writeCheckpoint();
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n  AgentSID — Runtime Mutation Scan (Pull-Rug Detection)");
  console.log(`  Started: ${new Date().toISOString()}`);
  console.log(`  Workers: ${WORKERS} | Timeout: ${TIMEOUT_MS / 1000}s/server\n`);
  console.log("  Methodology: snapshot tools/list → invoke one safe read-only tool → snapshot again → diff");

  const existing = loadExistingOutput();
  if (existing) {
    mergeExisting(existing);
    console.log(`\n  Resuming from checkpoint: ${state.counters.total} servers already scanned`);
  }

  const allServers = loadServersFromReports();
  let queue = allServers.filter((s) => !state.donePackages.has(s.reportKey));
  if (LIMIT) queue = queue.slice(0, LIMIT);
  console.log(`  Eligible: ${allServers.length} | Queue: ${queue.length}\n`);

  if (queue.length === 0) {
    console.log("  Nothing to do. Use --fresh to restart.");
    printFinalSummary();
    return;
  }

  process.on("SIGINT", () => {
    console.log("\n\n  Caught SIGINT — writing checkpoint...");
    writeCheckpoint();
    console.log("  Saved. Re-run to resume.");
    process.exit(0);
  });

  await runWorkerPool(queue);
  printFinalSummary();
}

function printFinalSummary() {
  console.log("\n  ═══ Mutation Scan Complete ═══\n");
  console.log(`  Total scanned: ${state.counters.total}`);
  console.log(`  Stable manifests: ${state.counters.stable}`);
  console.log(`  MUTATED manifests: ${state.counters.mutated}`);
  console.log(`    → with tools/list_changed notification: ${state.counters.listChangedEmitted}`);
  console.log(`    → silent mutation: ${state.counters.mutated - state.counters.listChangedEmitted}`);
  console.log(`  Skipped (no safe tool to invoke): ${state.counters.noSafeTool}`);
  console.log(`  Errors: ${state.counters.errors} (list A: ${state.counters.listAFailed}, list B: ${state.counters.listBFailed})`);

  if (state.mutatedServers.length > 0) {
    console.log(`\n  Mutated servers (top 20):`);
    for (const s of state.mutatedServers.slice(0, 20)) {
      console.log(`    ${s.package} — ${s.changes.length} changes, listChanged=${s.listChangedFired}`);
      for (const c of s.changes.slice(0, 3)) {
        console.log(`      [${c.type}] ${c.tool}`);
      }
    }
  }

  console.log(`\n  Output: ${OUT_FILE}\n`);
}

main().catch((e) => {
  console.error("\n  FATAL:", e);
  writeCheckpoint();
  process.exit(1);
});
