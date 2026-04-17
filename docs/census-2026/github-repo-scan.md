# GitHub-Only MCP Server Census — 2026-04-17

**Author:** recon (scanner/research) · **Data:** `github-repo-scan.json` · **Scanner:** v0.3.0

## Summary

A targeted GitHub crawl surfaced **6,633 unique repositories** plausibly related to Model Context Protocol. After filtering against the 15,983-entry `registry-index.json` (which is keyed off npm + PyPI), **371 were confirmed MCP servers by manifest dependency** — but were NOT in our registry. Of those:

| Bucket | Count | Interpretation |
|---|---|---|
| Published on npm/PyPI, missing from registry | **251** | **Registry coverage gap.** The crawler that builds `registry-index.json` is not discovering these. Immediate backfill job for Forge. |
| GitHub-only (no npm/PyPI publication detected) | **114** | Genuinely novel surface area. The registry cannot see these because they are not published — they are installed by `git clone` + `pip install -e .` or `npm install .` |
| Total missing | **365** | |

Of the 114 GitHub-only repos, **55 had tool definitions recoverable via static source analysis** (after a second-pass extractor that added Go `server.AddTool` patterns, broader TS host identifiers, and a wider file budget). When graded with the production scanner (same calibration as the public registry):

| Grade | Count | % |
|---|---|---|
| A | 0 | 0% |
| B | 4 | 7% |
| C | 12 | 22% |
| D | 17 | 31% |
| F | 22 | 40% |

**71% graded D or F** (39/55) — comparable to the distribution in the npm/PyPI registry, suggesting unpublished repos are not systematically safer or riskier than published ones. This refutes any "the bad ones are published, the good ones live on GitHub" hypothesis.

**Two CRITICAL findings** in this expanded set (vs zero in the first-pass 28-repo sample):
- `jdez427/claude-ipc-mcp` (130⭐, score 3/100, F) — 2 CRITICAL + 1 HIGH findings. Lowest score of any GitHub-only MCP server scanned.
- `coleam00/remote-mcp-server-with-auth` (292⭐, score 16/100, F) — 2 CRITICAL findings on a server that markets itself as "with auth".

## Method

1. `gh search repos` across six queries covering topic filters (`model-context-protocol`, `mcp-server`, `mcp`) and keyword filters (`mcp-server in:name`, `modelcontextprotocol in:readme`) with both default and `sort:updated` orderings to sidestep GitHub's 1,000-result cap per query. Deduped on `full_name`.
2. Filter out `awesome-*` lists and meta repos by name; require `mcp` in repo name OR an MCP-related topic. (4,218 candidates remained from 6,633.)
3. Took the top 300 by stars plus 300 more whose name contained `mcp-server`/`-mcp`, total 600 for classification.
4. For each, fetched `package.json` / `pyproject.toml` / `requirements.txt` / `Cargo.toml` / `go.mod` via `raw.githubusercontent.com` to detect MCP SDK deps (`@modelcontextprotocol/sdk`, `mcp`, `fastmcp`, `mark3labs/mcp-go`). Classified 371 as confirmed MCP servers.
5. Dedupe vs `registry-index.json` using slugified `owner-repo`, bare `repo`, and `name_from_manifest`.
6. Published-status check: `npm view <pkg> version` for node repos, `pypi.org/pypi/<pkg>/json` HTTP 200 for Python.
7. Regex-extracted tool defs from all 114 GitHub-only repos. Pattern set covers Python (`@mcp.tool`, `@server.tool`, `Tool(name=..., description=...)`), TypeScript/JavaScript (`server.tool(...)`, `registerTool(...)`, `addTool(...)`), Go (`mcp.NewTool(...)`, `server.AddTool(...)`), and Rust (`add_tool`, `register_tool`). 55 yielded ≥1 tool.
8. Ran `scanToolDescriptions → scanToxicDataFlows → applyMitigations → grade` directly against extracted defs with `scanner/src/rules.mjs` v0.3.0.

### Limits worth naming

- **Static extraction is conservative.** Tools registered via config files, dynamic loops, or decorator-generated factories are missed. Real tool counts per repo are likely higher, not lower.
- **No runtime scan.** Running `npx` or `pip install -e .` against arbitrary GitHub repos executes third-party install scripts. That's scoped to a sandbox and explicit per-repo approval — not done here.
- **Input schemas not extracted.** The grader's schema-based mitigations (e.g., "constrained enum → lower severity") can't fire, so scores skew slightly low. To calibrate, the two `B`-grade repos (excalidraw-mcp, better-chatbot) should be treated as the ceiling this method can hit, not an absolute.
- **Tool count for hexstrike-ai (150) is regex-reported** from multi-tool registration blocks; spot-check would confirm.

## Worst offenders (GitHub-only, graded)

| Grade | Score | Stars | Repo | Tools | Signal |
|---|---|---|---|---|---|
| F | **3** | 130 | [jdez427/claude-ipc-mcp](https://github.com/jdez427/claude-ipc-mcp) | 9 | **2 CRITICAL** + 1 HIGH. Lowest score in the whole set. Inter-process-communication surface with no access controls. |
| F | 15 | 8,149 | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 150 | "MCP server that lets AI run offensive-security tooling." Every tool is a destructive/network op. 142 HIGH findings. |
| F | 15 | 353 | [MorDavid/BloodHound-MCP-AI](https://github.com/MorDavid/BloodHound-MCP-AI) | 75 | BloodHound AD-enumeration bridge. By design invasive; no auth tools detected. |
| F | 16 | 292 | [coleam00/remote-mcp-server-with-auth](https://github.com/coleam00/remote-mcp-server-with-auth) | 4 | **2 CRITICAL** on a server marketing itself as authenticated. Textbook irony. |
| F | 16 | 200 | [mpeirone/zabbix-mcp-server](https://github.com/mpeirone/zabbix-mcp-server) | 44 | Monitoring-system bridge, 45 HIGH findings. |
| F | 17 | 388 | [zinja-coder/jadx-mcp-server](https://github.com/zinja-coder/jadx-mcp-server) | 29 | APK reverse-engineering bridge. |
| F | 18 | 160 | [robcerda/monarch-mcp-server](https://github.com/robcerda/monarch-mcp-server) | 19 | Personal-finance API bridge with 10 HIGH. |
| F | 21 | 784 | [WJZ-P/gemini-skill](https://github.com/WJZ-P/gemini-skill) | 17 | |
| F | 22 | 906 | [jjsantos01/qgis_mcp](https://github.com/jjsantos01/qgis_mcp) | 15 | QGIS driver — file/process access. |
| F | 22 | 582 | [6551Team/opentwitter-mcp](https://github.com/6551Team/opentwitter-mcp) | 15 | |
| F | 22 | 293 | [Dakkshin/after-effects-mcp](https://github.com/Dakkshin/after-effects-mcp) | 13 | Adobe After Effects driver. |
| F | 22 | 282 | [joenorton/comfyui-mcp-server](https://github.com/joenorton/comfyui-mcp-server) | 15 | ComfyUI (Stable Diffusion workflow) bridge. |
| F | 24 | 244 | [pwno-io/pwno-mcp](https://github.com/pwno-io/pwno-mcp) | 12 | Self-described "Pwn" server — another offensive-security cluster. |
| F | 32 | 1,052 | [microsoft/lets-learn-mcp-python](https://github.com/microsoft/lets-learn-mcp-python) | 8 | Microsoft-branded teaching server. Worth flagging — students copy this pattern. |
| F | 33 | 8,600 | [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) | 7 | Framework repo. The example server inside it grades F. |
| F | 36 | 339 | [assafelovic/gptr-mcp](https://github.com/assafelovic/gptr-mcp) | 5 | gpt-researcher MCP bridge. |
| F | 37 | 929 | [6551Team/opennews-mcp](https://github.com/6551Team/opennews-mcp) | 13 | |
| F | 38 | 881 | [arben-adm/mcp-sequential-thinking](https://github.com/arben-adm/mcp-sequential-thinking) | 5 | |

## Notable enterprise hits

| Grade | Repo | Why it matters |
|---|---|---|
| D(48) | [docker/hub-mcp](https://github.com/docker/hub-mcp) (134⭐) | Docker-maintained; 13 tools, 2 HIGH. |
| D(58) | [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge) (3,584⭐) | Vendor-branded "enterprise" MCP gateway, still grades D. |
| C(72) | [TencentCloudBase/CloudBase-MCP](https://github.com/TencentCloudBase/CloudBase-MCP) (992⭐) | Tencent's cloud MCP bridge. |
| C(74) | [langfuse/mcp-server-langfuse](https://github.com/langfuse/mcp-server-langfuse) (160⭐) | Langfuse observability. |
| F(33) | [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) (8,600⭐) | The de-facto Go SDK. Example server sets a bad example. |
| F(32) | [microsoft/lets-learn-mcp-python](https://github.com/microsoft/lets-learn-mcp-python) (1,052⭐) | Labeled `lets-learn` — influences every Python tutorial that follows. |
| D(44) | [weaviate/mcp-server-weaviate](https://github.com/weaviate/mcp-server-weaviate) (161⭐) | Weaviate's own MCP bridge. |

## Registry coverage gap (published but missing — top 15 by stars)

These are MCP servers *actually published* on npm/PyPI that our registry hasn't picked up. Immediate backfill candidates:

| Stars | Repo | Registry (npm/PyPI) |
|---|---|---|
| 26,511 | assafelovic/gpt-researcher | `gpt-researcher` (PyPI) |
| 14,408 | GLips/Figma-Context-MCP | `figma-developer-mcp` (npm) |
| 12,868 | yusufkaraaslan/Skill_Seekers | `skill-seekers` (PyPI) |
| 11,811 | tadata-org/fastapi_mcp | `fastapi-mcp` (PyPI) |
| 8,443 | LaurieWired/GhidraMCP | `GhidraMCP` (PyPI) |
| 7,829 | Upsonic/Upsonic | `upsonic` (PyPI) |
| 6,661 | grab/cursor-talk-to-figma-mcp | `cursor-talk-to-figma-mcp` (npm) |
| 5,234 | getsentry/XcodeBuildMCP | `xcodebuildmcp` (npm) |
| 5,139 | CursorTouch/Windows-MCP | `windows-mcp` (PyPI) |
| 4,963 | sooperset/mcp-atlassian | `mcp-atlassian` (PyPI) |
| 4,140 | open-webui/mcpo | `mcpo` (PyPI) |
| 3,973 | antvis/mcp-server-chart | `@antv/mcp-server-chart` (npm) |
| 3,747 | evalstate/fast-agent | `fast-agent-mcp` (PyPI) |
| 3,708 | haris-musa/excel-mcp-server | `excel-mcp-server` (PyPI) |

Full list of 251 in `github-repo-scan.json → published_missing`.

## Paper angle (for voice)

Three story beats, any of which can carry a post:

1. **"The 251 gap."** Our public registry — and, by extension, any grade-your-MCP tool keyed off npm/PyPI — is missing 251 publicly-published MCP servers with non-trivial adoption. Coverage is not what it looks like. Methodology matters. Suggested title: *Registry blind spots: what npm and PyPI don't index.*
2. **"The GitHub-only underbelly."** 114 MCP servers distribute by `git clone`. They never hit a package registry — so they never hit a supply-chain audit, never get a trust score, and never show up in any census. 71% of the scannable subset graded D/F using the same rules as our published-tool census. Suggested title: *Installed by git clone: the MCP servers no registry can see.*
3. **"Offensive-by-design."** hexstrike-ai (8.1k⭐), BloodHound-MCP-AI, jadx-mcp-server, ENScan-GO, slackdump — there is a cohort of MCP servers whose explicit purpose is offensive security or unauthenticated data extraction. They are not bugs; they are features. The question they force is governance, not scoring. Suggested title: *Weaponized by design: MCP servers built to break things.* (Note: overlaps with prior paper `scanner/docs/census-2026/weaponized-by-design.md`, can be combined.)

## Follow-ups for the team

- **Forge / Smith:** backfill task — ingest the 251 `published_missing` packages into `registry-index.json` (just point the existing crawler at this list).
- **Smith:** the GitHub Action (mcp-security-gate) should have a `--github-only` mode that can static-scan a repo's own tool defs without requiring registry membership. The regex set here is the seed.
- **Voice:** pick a story beat above. "The 251 gap" is the most defensible because the data is factual and the action is obvious (fix the registry); "Offensive-by-design" is the most shareable but needs careful framing.
- **Cap:** want recon to keep walking the long tail (next 600-repo batch) for a more complete census, or pivot to runtime sandboxed scans of the top 10 GitHub-only repos for deeper findings?

## Data files

- `github-repo-scan.json` — full structured output (method, per-repo scores, both lists).
- Corpus notes live at `/tmp/recon-crawl/` on the recon host — not committed (raw crawl output, ~30 MB).
