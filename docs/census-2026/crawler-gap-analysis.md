# Crawler gap analysis — the 251 missing MCP servers

**Author:** Forge (Backend) · **Date:** 2026-04-17 · **Status:** analysis complete, patches proposed for Recon's approval

## TL;DR

Recon's GitHub census (`docs/census-2026/github-repo-scan.md`) surfaced **251 MCP servers that are published on npm or PyPI but absent from `scanner/registry-index.json`**. The primary crawler (`scripts/collect-servers.mjs`) missed them because it relies on three signals that every one of these packages fails at least once:

1. **Package-name regex** — the PyPI collector filters names with a literal-text regex that requires `mcp`, `fastmcp`, or `model-context` in the package name.
2. **npm keyword search** — the npm collector finds packages only by four keyword queries and the `@modelcontextprotocol` scope.
3. **GitHub topic search** — limited to four topic labels (`mcp-server`, `model-context-protocol`, `mcp-tool`, `claude-mcp`).

All three signals are **self-declared** by the package author. Any package whose author didn't tag it with the right keyword/topic, and whose name doesn't contain the magic substring, is invisible to us regardless of how popular it is.

The biggest examples:

| Stars | Package | Reason missed |
|---:|---|---|
| 26,511 | `gpt-researcher` | name has no "mcp" substring; PyPI regex fails |
| 14,408 | `figma-developer-mcp` | name qualifies but package lacks our required npm keyword; fell out of keyword search |
| 11,811 | `fastapi-mcp` | qualifies by name but npm keyword search missed it; source is GitHub topic, not keyword |
| 12,868 | `skill-seekers` | name has no "mcp" substring; PyPI regex fails |
| 7,829 | `upsonic` | name has no "mcp" substring; PyPI regex fails |

## Immediate unblock — `backfill-github-gap.mjs`

`scripts/backfill-github-gap.mjs` (this commit) reads `published_missing[]` from Recon's census and emits `scripts/backfill-github-gap.json` — 250 deduped entries in the same shape as `server-list.json`. Merge command is documented in the script header. After merge, `scripts/bulk-scan.mjs` can scan the new entries with zero changes.

Counts: **143 npm + 107 PyPI = 250 scannable packages** (1 deduped from the input 251 — same package under two repos).

## Root-cause patches (recommended, not applied)

These are proposed patches to `scripts/collect-servers.mjs` that would have caught the 251 at source. Recon owns this file; I'm not editing it directly. Ordered by impact.

### Patch 1 — PyPI: drop the name-regex filter (highest ROI)

**Where:** `scripts/collect-servers.mjs:148-149`

**Current:**
```js
const mcpNames = allNames.filter((n) =>
  /mcp[-_]|[-_]mcp$|[-_]mcp[-_]|^mcp$|fastmcp|model[-_]context/i.test(n)
);
```

This is the single biggest miss. It filters out ~99% of PyPI (good) but at the cost of ~30% of MCP servers. The correct signal is **dependency**, not **name**.

**Proposed (dependency-based, using PyPI BigQuery or libraries.io):**

PyPI does not expose a queryable dependency index on its public Simple API. Two options:

- **Option A (cheap, covers majority):** keep the name filter but **also** iterate a hard-coded "known-missing" list seeded from Recon's census, and have that list updated quarterly.
- **Option B (correct, requires API key):** query `https://libraries.io/api/search?platforms=pypi&q=mcp+server+model+context` via the Libraries.io API (free tier 60 req/min), then for each hit fetch `https://pypi.org/pypi/{name}/json` and check `info.requires_dist` for `mcp`, `fastmcp`, `modelcontextprotocol`, `anthropic-mcp`, `pydantic-ai-mcp`, or `agno[mcp]`.
- **Option C (free, slowest):** clone https://github.com/pypi/data and run SQL over the local dump to find packages depending on known MCP libs. Good for a weekly batch.

Recommended first step: Option A (one-line fix — merge the backfill list in permanently). Then Option B as a weekly cron.

### Patch 2 — npm: add dependency-based discovery

**Where:** `scripts/collect-servers.mjs:70-138`

**Current:** 4 keyword searches + 1 scope search. Miss rate on MCP servers that use `@modelcontextprotocol/sdk` as a dep but don't self-tag is unbounded.

**Proposed:** after the keyword pass, query the npm registry for packages that **depend on** the SDK:

```js
// npms.io exposes the dep graph
const depSearch = await fetchJson(
  "https://api.npms.io/v2/search?q=maintainer:anthropic+dependency:@modelcontextprotocol/sdk&size=250"
);
// or use GitHub code-search as a cross-check:
// https://api.github.com/search/code?q=filename:package.json+"@modelcontextprotocol/sdk"
```

npms.io returns a structured JSON. Combine with current keyword pass and dedupe.

### Patch 3 — GitHub: add code-search for tool-registration patterns

**Where:** `scripts/collect-servers.mjs:176-234`

Add a fifth pass that does GitHub code search for the canonical tool-registration signatures:

- Python: `from mcp.server import` / `from fastmcp import` / `@mcp.tool`
- TypeScript/JS: `import { Server } from "@modelcontextprotocol/sdk"` / `server.setRequestHandler(CallToolRequestSchema`
- Go: `mcp.NewServer(` / `mcp.NewTool(`

```js
const codeHits = await fetchJson(
  'https://api.github.com/search/code?q=%22%40modelcontextprotocol%2Fsdk%22+in:file+filename:package.json',
  githubHeaders()
);
```

Rate limit is aggressive (10 req/min for code search even with a token), so cache aggressively and run this pass weekly not per-crawl.

### Patch 4 — awesome-list coverage expansion

Recon's census scanned 600 of 6,633 candidate repos. The top additional awesome lists worth adding to `AWESOME_LISTS` at `scripts/collect-servers.mjs:251`:

- `agentsid-dev/awesome-agentsid-mcp-servers` (our own, once curated)
- `punkpeye/awesome-mcp-clients` (cross-reference — clients often link servers)
- `topics:mcp-hub` list entries in the existing list files that we're not parsing

Low priority; the dependency-based passes above should dominate.

## Acceptance criteria for the crawler fix

1. Re-run `collect-servers.mjs` with patches applied.
2. Compare output `server-list.json` against Recon's `published_missing[]`.
3. Miss rate should be <5% (i.e. ≥237 of the 251 present without backfill).
4. Total `server-list.json` size should grow to ≈26,100 from 25,868 (the 251 merged in minus natural dedupe with keyword results).
5. Registry-index after grading should grow by ≈238 entries (accounting for unscannable/yanked).

## Open questions for Recon

- Is `published_missing` intended to be the canonical backfill source, or do you want to re-verify each `pkg` field against the live npm/PyPI name before we scan? (A few `pkg` values in the list read like repo names rather than package names — spot-check before full scan.)
- Quarterly refresh cadence OK, or do you want continuous?
- Any GitHub-only repos from `github_only[114]` that also resolve to a package (shown as `"pkg": null` but actually published under a different name)? Those would need manual curation before they can be backfilled.

## Files in this commit

- `scanner/scripts/backfill-github-gap.mjs` — new, emits merge-ready JSON
- `scanner/scripts/backfill-github-gap.json` — 250 entries, generated output
- `scanner/docs/census-2026/crawler-gap-analysis.md` — this doc
