#!/usr/bin/env node
/**
 * Backfill script for "the 251 gap" — MCP servers present on npm/PyPI but
 * missing from scanner/registry-index.json because the primary crawler
 * (scripts/collect-servers.mjs) didn't surface them.
 *
 * Source: scanner/docs/census-2026/github-repo-scan.json · published_missing[]
 * Each entry: { full_name, pkg, category: "node-mcp"|"python-mcp"|..., stars }
 *
 * Output: scanner/scripts/backfill-github-gap.json — shape-compatible with
 * server-list.json so the existing bulk-scan.mjs can consume it with a
 * one-line merge (see README for the exact command).
 *
 * Usage:
 *   node scripts/backfill-github-gap.mjs
 *
 *   # then merge into server-list (safe — dedupes by `id`):
 *   node -e "\
 *     const base = JSON.parse(require('fs').readFileSync('scripts/server-list.json')); \
 *     const add  = JSON.parse(require('fs').readFileSync('scripts/backfill-github-gap.json')); \
 *     const ids  = new Set(base.servers.map(s => s.id)); \
 *     const merged = base.servers.concat(add.servers.filter(s => !ids.has(s.id))); \
 *     base.servers = merged; base.stats.backfill_added = merged.length - ids.size; \
 *     require('fs').writeFileSync('scripts/server-list.json', JSON.stringify(base, null, 2)); \
 *     console.log('added', merged.length - ids.size);"
 *
 *   # then re-run bulk scan normally:
 *   node scripts/bulk-scan.mjs
 *
 * Why this is a separate script, not a patch to collect-servers.mjs:
 *   1. Unblocks grading of 251 known-missing packages immediately.
 *   2. Keeps the collect pipeline pure — no one-off hardcoded sources.
 *   3. The upstream crawler-gap fix (extend PyPI regex, add dependency-based
 *      discovery) is proposed separately in
 *      scanner/docs/census-2026/crawler-gap-analysis.md.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const IN_PATH = path.resolve(
  __dirname,
  "..",
  "docs",
  "census-2026",
  "github-repo-scan.json"
);
const OUT_PATH = path.resolve(__dirname, "backfill-github-gap.json");

const SOURCE_LABEL = "github-repo-scan-backfill:census-2026";

/** Map scan-json category → runtime + id-prefix + command-template. */
const CATEGORY_MAP = Object.freeze({
  "node-mcp": {
    runtime: "node",
    idPrefix: "npm:",
    command: (pkg) => `npx -y ${pkg}`,
  },
  "python-mcp": {
    runtime: "python",
    idPrefix: "pypi:",
    command: (pkg) => `uvx ${pkg}`,
  },
});

function readScanInput() {
  if (!fs.existsSync(IN_PATH)) {
    throw new Error(
      `Expected scan output at ${IN_PATH} — run recon's github-repo-scan first`
    );
  }
  return JSON.parse(fs.readFileSync(IN_PATH, "utf-8"));
}

function transformEntry(entry) {
  const mapping = CATEGORY_MAP[entry.category];
  if (!mapping) {
    // Go MCPs etc. don't have a package-manager path we can scan — skip.
    return null;
  }
  if (!entry.pkg || !entry.full_name) return null;

  return {
    id: `${mapping.idPrefix}${entry.pkg}`,
    name: entry.pkg,
    package: entry.pkg,
    command: mapping.command(entry.pkg),
    runtime: mapping.runtime,
    sources: [SOURCE_LABEL],
    repo: `https://github.com/${entry.full_name}`,
    downloads: 0,
    description: "",
    lastPublished: null,
    stars: entry.stars ?? 0,
  };
}

function main() {
  const input = readScanInput();
  const missing = Array.isArray(input.published_missing)
    ? input.published_missing
    : [];
  if (missing.length === 0) {
    throw new Error("published_missing[] is empty or absent in scan JSON");
  }

  // Dedupe inside the input too — a pkg can appear under two repos.
  const byId = new Map();
  let skipped = 0;
  for (const entry of missing) {
    const transformed = transformEntry(entry);
    if (!transformed) {
      skipped++;
      continue;
    }
    if (!byId.has(transformed.id)) {
      byId.set(transformed.id, transformed);
    }
  }

  const servers = Array.from(byId.values()).sort((a, b) => b.stars - a.stars);

  const output = {
    generated: new Date().toISOString(),
    source: "scanner/docs/census-2026/github-repo-scan.json",
    sourceLabel: SOURCE_LABEL,
    stats: {
      input_total: missing.length,
      skipped_unsupported_category: skipped,
      deduped: servers.length,
      node: servers.filter((s) => s.runtime === "node").length,
      python: servers.filter((s) => s.runtime === "python").length,
    },
    servers,
  };

  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2));
  process.stderr.write(
    `Wrote ${servers.length} backfill entries → ${OUT_PATH}\n` +
      `  node:   ${output.stats.node}\n` +
      `  python: ${output.stats.python}\n` +
      `  skipped: ${skipped} (non-package categories)\n`
  );
}

main();
