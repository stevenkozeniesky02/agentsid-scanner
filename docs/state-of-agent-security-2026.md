# The State of MCP Server Security — 2026

**An empirical analysis of 100 Model Context Protocol servers**

AgentsID Research · March 2026

---

## Abstract

In an audit of 100 MCP (Model Context Protocol) server packages — including the "gold standard" reference implementations maintained by Anthropic and Microsoft — every vendor-maintained server that exposed tools received a failing grade (F). Across the broader ecosystem, 71% of servers scored F. Zero scored A. We identified 893 total findings across 41 servers exposing 485 tools, including 163 instances of a novel vulnerability class we term "hallucination-based vulnerabilities" (HBVs) — security weaknesses unique to LLM-driven tool execution where vague or ambiguous tool definitions cause the language model to over-privilege, misroute, or behave unpredictably. Our scanner identifies the exact structural preconditions — unbounded string parameters, missing schema validation, vague scope boundaries — that led to the RCE-class CVEs disclosed against MCP servers in early 2026 (CVE-2025-68143, CVE-2025-68144, CVE-2025-9611). These findings demonstrate that the MCP specification is vulnerable by default: the protocol prioritizes developer flexibility over the schema strictness and semantic validation required for safe autonomous operation, and its own reference implementations confirm that insecurity is the path of least resistance.

---

## 1. Introduction

The Model Context Protocol (MCP), introduced by Anthropic in November 2024 and adopted by OpenAI, Google, Microsoft, and Amazon, has become the de facto standard for connecting AI agents to external tools. As of March 2026, the MCP ecosystem has over 97 million monthly SDK downloads and more than 5,200 registered servers.

MCP solves a real problem: it standardizes how AI models discover and call tools. But the protocol's security model is minimal by design. The MCP specification delegates authentication to the transport layer, provides no mechanism for per-tool authorization, defines no standard for agent identity, and includes no audit log format.

The result is an ecosystem where AI agents have unrestricted access to every tool a server exposes. An agent connecting to a database MCP server can SELECT and DROP with equal ease. An agent with a shell MCP server can `ls` and `rm -rf /` without distinction.

This report quantifies the scope of that problem.

### 1.1 Prior Work

Previous security analyses of MCP servers include the Astrix Security state of MCP security report (2025), which found that 88% of MCP servers require credentials and only 8.5% use OAuth. Qualys TotalAI identified MCP servers as "the new shadow IT" for AI in March 2026. Individual vulnerability disclosures (CVE-2025-6514, the Postmark MCP supply chain attack) have demonstrated specific attack vectors. However, no prior study has systematically scanned a large sample of MCP servers against a standardized security framework, and no prior work has identified hallucination-based vulnerabilities as a distinct security category.

### 1.2 Contributions

This report makes three contributions:

1. **Empirical data**: Security analysis of 100 MCP server packages, with detailed findings across 41 servers exposing 485 tools.
2. **Novel vulnerability class**: Identification and taxonomy of hallucination-based vulnerabilities — security issues that arise from the interaction between tool definitions and LLM reasoning, rather than from code-level flaws.
3. **Security grading framework**: A reproducible methodology for evaluating MCP server security across six categories.

---

## 2. Methodology

### 2.1 Scanner Design

We built an automated scanner (open-source, available at github.com/AgentsID-dev/agentsid-scanner) that connects to MCP servers via the stdio transport protocol, performs the standard MCP handshake (initialize → notifications/initialized → tools/list), and analyzes the returned tool definitions.

The scanner evaluates seven categories of security risk:

| Category | What It Checks |
|----------|---------------|
| **Injection** | 11 prompt injection patterns in tool descriptions |
| **Permissions** | Tool names classified by risk level (destructive, execution, financial, credential) |
| **Validation** | Input schema completeness and constraint enforcement |
| **Auth** | Authentication indicators in the tool surface |
| **Secrets** | Potential credential exposure in tool outputs |
| **Output** | Unfiltered sensitive data in responses |
| **Hallucination** | 7 classes of LLM-reasoning vulnerabilities (see Section 4) |

### 2.2 Grading Scale

Each server starts at 100 points. Deductions are applied per finding:

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |

Letter grades: A (90-100), B (75-89), C (60-74), D (40-59), F (0-39). The floor is 0.

### 2.3 Sample Selection

We scanned 100 MCP server packages from the npm registry, selected by:
- The top 50 MCP-related packages by GitHub stars
- The top 50 results for npm searches across "mcp server", "mcp tool", "mcp agent", and "model context protocol"
- Deduplication by package name

Of these 100, 41 (41%) successfully exposed tool definitions via the stdio transport. The remaining 59 required API keys, external service authentication, or specific runtime configurations that prevented tool enumeration.

**The Visibility Gap**: This 41% scan rate is itself a critical finding. 59% of MCP servers are opaque to independent security review — there is no standardized health-check endpoint, no unauthenticated tool-listing capability, and no way for a security researcher (or a developer evaluating a server) to assess the tool surface before connecting an agent. The ecosystem is not just insecure — it is unauditable. This opacity should be addressed in the MCP specification through a mandatory, unauthenticated `/tools/list` introspection endpoint.

### 2.4 Limitations and Design Decisions

**Static analysis, not runtime analysis.** The scanner analyzes tool definitions (names, descriptions, schemas), not runtime behavior. A tool that validates input internally would not receive credit for that validation in our scan. Some servers may have security features not visible through tool definitions.

**Sample scope.** The sample is limited to npm packages accessible via npx. Python-only, Go-only, and private MCP servers are not included. The 100 packages were selected by popularity (stars, download rank), not randomly — this means our sample skews toward the most visible and presumably best-maintained servers, which makes the results more damning, not less.

**Injection detection uses regex, not semantic analysis.** Our current detection engine utilizes 11 regex-based patterns for known injection strings. We acknowledge that regex is a sieve — a sophisticated attacker will not write "ignore previous instructions" but rather embed adversarial intent in natural-sounding phrasing that static patterns cannot catch. However, as the first large-scale audit of over 100 MCP servers, this baseline establishes a vulnerability floor. If 11 simple patterns find issues in 1% of servers, semantic analysis will find substantially more. Future iterations (v2) will incorporate LLM-based "judge" evaluation to detect semantic bypasses that static analysis misses.

**HBV-4 (short descriptions) as a vulnerability, not a linting issue.** While short descriptions may traditionally be viewed as a documentation concern, in agentic workflows they represent semantic vulnerabilities. When a tool like `puppeteer_navigate` provides only 17 characters of context, the LLM is forced to rely on internal priors to guess parameter structure and intent. This creates non-deterministic runtime behavior — the same tool invoked by Claude, GPT, and Gemini may produce three different parameter sets. In production-grade agents, non-deterministic tool invocation is an unacceptable risk.

**We grade against a standard that does not yet exist.** The MCP specification currently prioritizes developer flexibility over security hardening. This audit intentionally grades against an advanced security posture — mandatory bounded schemas, explicit required fields, scoped tool descriptions — that the protocol does not yet mandate. If vendors made schemas strict and descriptions precise, tools might become harder for LLMs to use casually. We believe that trade-off is correct: an agent that fails safely is better than one that executes unpredictably. By grading against this standard, we expose the systemic validation gap where protocol flexibility actively facilitates agentic failure modes.

**The `browser_press_key` false positive.** Our dangerous-tool-name regex flagged `browser_press_key` as credential_access because the name contains "key." This is a false positive — the tool presses keyboard keys, not cryptographic keys. We include this transparently as an example of where regex-based name classification breaks down, and as motivation for the semantic analysis planned in v2. Notably, this single false positive did not drive Playwright's F grade — 24 schema validation failures did. The grading algorithm is weighted toward schema integrity over naming heuristics.

---

## 3. Results

### 3.1 Overall Findings

| Metric | Value |
|--------|-------|
| Packages scanned | 100 |
| Servers with tool definitions | 41 |
| Total tools analyzed | 485 |
| Average tools per server | 11.8 |
| Total findings | 893 |
| Average findings per server | 21.8 |

### 3.2 Grade Distribution

| Grade | Count | Percentage |
|-------|-------|------------|
| A (90-100) | 0 | 0% |
| B (75-89) | 2 | 5% |
| C (60-74) | 3 | 7% |
| D (40-59) | 7 | 17% |
| F (0-39) | 29 | 71% |

**71% of MCP servers scored F. No server scored A.**

The two B-grade servers were single-tool servers with minimal attack surface (1 tool each). The three C-grade servers had 1-2 tools with basic schema validation. Every server with more than 5 tools scored D or F.

**The Protocol-Level Ceiling**: These grades do not reflect developer incompetence. Under the current MCP specification, it is structurally difficult to achieve an A grade because the protocol provides no standard fields for per-tool authorization, agent identity declaration, or audit metadata. Server authors cannot implement what the specification does not define. The F grades are a measurement of the protocol's security gap, not individual developer failure. Even the official reference implementations — built by the MCP specification authors themselves — scored F, confirming that the problem is systemic.

### 3.3 Findings by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 18 | 2% |
| High | 82 | 9% |
| Medium | 625 | 70% |
| Low | 168 | 19% |

### 3.4 Findings by Category

| Category | Count | Percentage | Description |
|----------|-------|------------|-------------|
| Validation | 543 | 61% | Missing or incomplete input schemas |
| Hallucination | 163 | 18% | LLM-reasoning vulnerabilities |
| Permissions | 91 | 10% | Dangerous tools without access controls |
| Auth | 35 | 4% | Missing authentication indicators |
| Output | 30 | 3% | Unfiltered sensitive output |
| Secrets | 20 | 2% | Potential credential exposure |
| Injection | 11 | 1% | Prompt injection in tool descriptions |

### 3.5 Notable Servers

| Server | Tools | Score | Findings | Notes |
|--------|-------|-------|----------|-------|
| GitHub MCP (Anthropic) | 26 | F (0) | 45 | 9 HBVs, 9 uncontrolled mutations, 0/26 validated |
| European Parliament MCP | 61 | F (0) | 204 | 121 hallucination findings. Government server. |
| Playwright MCP (Microsoft) | 22 | F (0) | 28 | Browser automation with no input validation |
| Heroku MCP | 33 | F (0) | 42 | Cloud deployment tools unrestricted |
| Chrome DevTools MCP | 29 | F (0) | 37 | Browser control without permissions |
| Notion MCP (official) | 22 | F (0) | 26 | Document management unrestricted |
| Railway MCP | 14 | F (0) | 22 | Infrastructure deployment unrestricted |
| Filesystem MCP (official) | 14 | F (0) | 31 | File system access without boundaries |
| Memory MCP (official) | 9 | F (2) | 11 | 3 delete tools with zero controls |
| Slack MCP | 20 | F (0) | - | Messaging with no per-tool auth |

Three of the servers listed above are official reference implementations from the MCP specification authors. Their F grades indicate that the security gap is systemic, not a matter of individual developer negligence.

### 3.6 Gold Standard Audit: Vendor-Maintained Servers

To test whether the ecosystem's F-grade trend reflects community inexperience or a deeper structural problem, we conducted targeted scans of the most widely-used, vendor-maintained MCP servers — the reference implementations that developers treat as examples of how to build MCP servers correctly.

| Server | Maintainer | Tools | Grade | Validation | Permissions | Hallucination |
|--------|-----------|-------|-------|------------|-------------|---------------|
| **@modelcontextprotocol/server-github** | Anthropic | 26 | **F (0)** | F (0/26 validated) | F (9 mutation/deploy tools uncontrolled) | F (9 HBVs) |
| **@modelcontextprotocol/server-filesystem** | Anthropic | 14 | **F (0)** | F (0/14 validated) | B | D (4 HBVs, 2 HIGH) |
| **@playwright/mcp** | Microsoft | 22 | **F (0)** | F (0/22 validated) | B | — |
| **@notionhq/notion-mcp-server** | Notion | 22 | **F (0)** | F (0/22 validated) | A | — |
| **@modelcontextprotocol/server-puppeteer** | Anthropic | 7 | **F (21)** | D | — | A (1 short desc) |
| **@modelcontextprotocol/server-memory** | Anthropic | 9 | **F (0)** | B | F (3 delete tools, zero controls) | A |
| **@modelcontextprotocol/server-everything** | Anthropic | 13 | **F (0)** | F | — | — |

**Every vendor-maintained MCP server that exposed tools scored F.** Five of seven Anthropic-maintained servers — built by the authors of the MCP specification — scored F.

The most critical result is `@modelcontextprotocol/server-github`, Anthropic's official GitHub integration. It exposes 26 tools including `push_files` (classified as deployment risk), `create_or_update_file`, `fork_repository`, and `merge_pull_request` — all without input validation, per-tool permissions, or scope boundaries. Nine tools triggered hallucination-based vulnerabilities because their descriptions reference files, accounts, and repositories without specifying which ones the agent is allowed to touch. An agent connected to this server with a GitHub PAT can push to any repository, merge any PR, and fork any project the token has access to, with no tool-level guardrails.

These findings are not theoretical. In early 2026, the related `@modelcontextprotocol/server-git` was disclosed with CVE-2025-68143 (path traversal) and CVE-2025-68144 (argument injection) — both resulting from unbounded string parameters in git tool inputs. Our scanner identifies exactly the structural precursors to these RCE-class vulnerabilities: tools accepting arbitrary strings with no length limits, no pattern constraints, and no scope boundaries. The CVEs are the consequence; the unbounded schemas are the cause.

Microsoft's `@playwright/mcp` exposes 22 browser automation tools — navigate, evaluate JavaScript, upload files, press keys, run arbitrary code — with zero schema validation on any tool. Every string parameter is unbounded. An agent prompted with adversarial input could use `browser_evaluate` to execute arbitrary JavaScript in the context of any authenticated session the browser holds. This aligns with CVE-2025-9611 (DNS rebinding/CSRF in Playwright MCP), where the server's lack of input validation enabled cross-origin exploitation. Microsoft's defense — that the server was for "intended local usage" — underscores the problem: the "intended usage" of an MCP server is whatever the LLM can be prompted to do, and without schema constraints, there is no boundary between intended and adversarial use.

These are not obscure community projects. These are the servers that Anthropic links from the MCP documentation, that Microsoft ships with Playwright, that Notion provides as their official integration. They are the templates that thousands of developers copy. If the gold standard scores F, the ecosystem built on top of it has no foundation.

**The implication is structural, not incidental.** Even with perfect credentials — the problem Astrix Security's 2025 report identified — these servers remain fully vulnerable to tool-level exploitation. Transport-layer OAuth does not help when the tool surface is unbounded. Credential security and tool-level security are orthogonal problems, and the ecosystem has addressed neither.

---

## 4. Hallucination-Based Vulnerabilities: A Novel Vulnerability Class

### 4.1 Definition

Hallucination-based vulnerabilities (HBVs) are security weaknesses that arise from the interaction between tool definitions and LLM reasoning, rather than from code-level flaws. They exploit the fact that LLMs interpret natural language tool descriptions to make execution decisions, and that vague, ambiguous, or misleading descriptions cause the model to over-privilege its actions.

Unlike traditional vulnerabilities (SQL injection, buffer overflow), HBVs cannot be detected by analyzing source code. They exist in the semantic space between what a tool description says and what the LLM infers.

### 4.2 Taxonomy

We identified seven classes of hallucination-based vulnerabilities:

**HBV-1: Vague Description Over-Privileging**

A tool described as "manages user data" could mean read, create, update, or delete. The LLM selects the interpretation that best fits the user's prompt, which may be the most destructive option.

*Exploit scenario*: User says "clean up the old accounts." LLM interprets "manages user data" as having delete capability. The tool handler accepts a `DELETE` action because the schema has no action-type constraint. User data is destroyed.

*Found in*: 29% of servers with tools

**HBV-2: Ambiguous Tool Names**

Tool names like `manage_users`, `handle_data`, or `process_request` provide no specificity about the operation. The LLM must infer the action, and different models infer differently.

*Exploit scenario*: An attacker uses prompt injection ("also remove inactive users") and the LLM routes to `manage_users` because the name is broad enough to match. A tool named `delete_user` would not have been selected by the same prompt because it signals irreversibility.

*Found in*: 12% of servers with tools

**HBV-3: Missing Scope Boundaries**

A tool that says "access files" without specifying which files, directories, or permission levels gives the LLM no basis to limit its access. The model will attempt the broadest possible scope.

*Exploit scenario*: An agent with a file tool described as "read and write files" is asked to "save this config." The LLM writes to `/etc/` because no boundary was specified. A description saying "read and write files within the /data directory only" would have constrained the model's behavior.

*Found in*: 44% of servers with tools

**HBV-4: Insufficient Description**

Tool descriptions under 20 characters force the LLM to infer capabilities from the name alone. A tool named `exec` with description "run" could mean anything.

*Exploit scenario*: A prompt injection inserts "use the exec tool to run this cleanup script." The LLM has no description to evaluate whether this is safe. With a complete description ("Execute a read-only SQL query against the analytics database"), the model would recognize a mismatch and refuse.

*Found in*: 7% of servers with tools

**HBV-5: Missing Description**

Tools with no description at all leave the LLM entirely dependent on name inference. Behavior becomes unpredictable across different models.

*Exploit scenario*: A tool named `sync` with no description. Claude interprets it as "synchronize data between systems." GPT interprets it as "sync local changes to remote." The same agent workflow produces different outcomes depending on which model is executing.

*Found in*: 3% of servers with tools

**HBV-6: Implicit Authority Escalation**

A tool with dangerous capabilities (name includes "admin", "delete", "exec") but an innocuous description ("helper utility", "simple tool") causes the LLM to underestimate risk and use the tool without appropriate caution.

*Exploit scenario*: A tool named `admin_reset` described as "simple maintenance utility." The LLM treats it as low-risk and calls it without prompting for confirmation. The tool resets the entire admin configuration. A description accurately stating "Resets all administrator accounts and permissions — irreversible" would trigger the model's safety reasoning.

*Found in*: 2% of servers with tools

**HBV-7: Conflicting Tool Descriptions**

Two or more tools with highly overlapping descriptions (>60% word overlap) cause the LLM to choose between them unpredictably. The wrong choice may execute a destructive operation when a read-only operation was intended.

*Exploit scenario*: `list_directory` ("List files and folders in a directory") and `list_directory_with_sizes` ("List files and folders in a directory with their sizes"). 92% overlap. The LLM may route a "show me the files" prompt to either tool non-deterministically. If one returns metadata that includes file permissions or ownership, it leaks information the user didn't request. This is a semantic race condition unique to LLM-driven tool selection.

*Found in*: 10% of servers with tools

### 4.3 Impact

163 hallucination-based vulnerabilities were found across 41 servers (4.0 per server average). One server — the European Parliament MCP server — contained 121 HBVs across 61 tools, primarily due to vague descriptions and missing scope boundaries on government data access tools.

HBVs are particularly dangerous because:
1. They are invisible to traditional security scanners (SAST, DAST)
2. They are non-deterministic — the same tool definition may behave differently across LLM models
3. They cannot be fixed by patching code — they require rewriting tool descriptions
4. They compound: a vague description + missing scope boundary + large tool surface = unpredictable agent behavior at scale

---

## 5. Analysis

### 5.1 The Validation Crisis

61% of all findings were input validation issues — tools accepting arbitrary input with no schema constraints, no string length limits, no pattern validation, and no required fields.

This matters because MCP tools receive their arguments from the LLM, which constructs them from natural language. Without schema validation, the tool handler must defend against every possible input the model might generate, including adversarial inputs from prompt injection attacks.

### 5.2 The Permission Vacuum

10% of findings related to permission gaps — destructive, financial, or privilege-escalation tools exposed without any access control mechanism.

The MCP specification provides no standard for per-tool authorization. A server can declare tools, but it cannot declare which agents should be allowed to call which tools. This means every connected agent has access to every tool, regardless of its role, trust level, or the human who authorized it.

### 5.3 The Authentication Gap

35 servers (85%) showed no authentication-related tools or indicators. While the MCP specification now includes an OAuth 2.1 authorization framework (added March 2025), adoption is minimal. Most servers authenticate at the transport level (if at all) and make no distinction between authenticated agents.

### 5.4 Scale Correlates with Risk

Every server with more than 5 tools scored D or F. Tool count strongly correlates with security grade:

| Tool Count | Average Score | Average Grade |
|------------|--------------|---------------|
| 1-2 | 65 | C |
| 3-5 | 28 | F |
| 6-20 | 3 | F |
| 20+ | 0 | F |

This suggests that MCP server authors do not scale their security practices with their tool surface. Adding the 6th tool is the inflection point where security degrades catastrophically.

---

## 6. Recommendations

### For MCP Server Authors

1. **Validate all inputs** with complete schemas — required fields, string length limits, pattern constraints, and enum restrictions.
2. **Write specific tool descriptions** — "Read a single file by path from the /data directory" not "access files." Avoid vague verbs (manage, handle, process).
3. **Split ambiguous tools** — replace `manage_users` with `list_users`, `create_user`, `delete_user`. Each tool should do one thing.
4. **Add scope boundaries** to descriptions — specify which directories, databases, or resources a tool can access.
5. **Differentiate overlapping tools** — if two tools sound similar, clarify the distinction in both descriptions.

### For the MCP Specification

1. **Define a per-tool authorization standard** — the specification should include a mechanism for mapping agent identity to tool permissions, not just transport-level authentication.
2. **Require input schema validation** — tool definitions without complete input schemas should be flagged as non-compliant.
3. **Standardize audit log format** — every tool call should produce a structured audit entry with agent identity, tool name, parameters, result, and timestamp.
4. **Add agent identity to the protocol** — agents should have verifiable identities, not just transport-level sessions.
5. **Define delegation semantics** — when an agent spawns a sub-agent, the specification should define how permissions narrow.

### For Developers Using MCP Servers

1. **Scan before you connect** — run `npx @agentsid/scanner` against any MCP server before giving your agent access to it.
2. **Add per-tool permissions** — use middleware (e.g., AgentsID Guard) to restrict which tools each agent can call.
3. **Audit tool calls** — log every tool call with the agent identity, not just the action.
4. **Review tool descriptions** — the description your LLM reads is the description it acts on. Vague descriptions are security vulnerabilities.

---

## 7. Conclusion

The MCP ecosystem is growing fast — 97 million monthly SDK downloads, 5,200+ servers, adoption by every major AI company. But our scan of 100 MCP server packages reveals a security posture that is, to put it directly, failing.

71% of servers that exposed tools scored F on security. Zero scored A. The average server had 21.8 security findings. And a new class of vulnerability — hallucination-based vulnerabilities — accounts for 18% of all findings, a risk category that didn't exist before LLM-driven tool execution.

The gold standard audit makes the case definitive. Every vendor-maintained MCP server that exposed tools — including five of seven Anthropic reference implementations — scored F. The servers that the MCP specification authors ship as examples, that developers copy as templates, and that enterprises deploy as integrations are structurally vulnerable. The CVEs have already started arriving (CVE-2025-68143, CVE-2025-68144, CVE-2025-9611), and our scanner identifies the exact preconditions that made them possible.

The MCP specification has made significant progress on transport-level security (OAuth 2.1, PKCE). But transport-level authentication is orthogonal to tool-level security. An agent authenticated with a 2048-bit RSA key can still pass `rm -rf /` through an unbounded string parameter. OAuth does not validate tool inputs. PKCE does not enforce scope boundaries. The protocol has no answer for the per-tool authorization problem: which agent can call which tool, with what parameters, under what conditions, and who knows about it.

The MCP specification is **vulnerable by default**. It allows — and through its reference implementations, actively encourages — empty schemas, unbounded inputs, and vague tool descriptions. These are not oversights by individual developers; they are design choices in the protocol that make insecurity the path of least resistance. Schema strictness and semantic validation must move from optional best practice to protocol-level mandatory requirements.

Until the ecosystem addresses identity, permissions, and audit at the tool level — not just the transport level — MCP servers will remain the most under-secured component of the AI agent stack.

---

## Methodology Reproducibility

The scanner, grading methodology, and all 100 scan reports are open-source and publicly available:

- **Scanner**: github.com/AgentsID-dev/agentsid-scanner
- **Scan data**: github.com/AgentsID-dev/agentsid-scanner/tree/master/reports
- **Scanner methodology**: Documented in src/rules.mjs, src/grader.mjs

To reproduce any scan: `npx @agentsid/scanner -- npx <package-name>`

---

## Appendix C: Reference Implementation

The recommendations in Sections 6.1–6.3 are not theoretical. We built open-source tooling that implements each one, both to validate the recommendations and to provide a starting point for the ecosystem.

| Recommendation | Implementation | Status |
|----------------|---------------|--------|
| Per-tool authorization standard (§6.2.1) | **AgentsID Permission Specification** — 14 constraint types (schedule, rate limit, data classification, budget, sequence, session, risk score, IP allowlist, chain depth, cooldown, anomaly detection, approval gates) for defining what an agent can do at tool-level granularity. Open RFC at agentsid.dev/spec. | Published, open for comment |
| Input schema validation (§6.2.2) | **AgentsID Security Scanner** — the tool used to produce this report. Evaluates tool schemas, descriptions, injection patterns, and hallucination-based vulnerabilities. | Open-source: github.com/AgentsID-dev/agentsid-scanner |
| Audit log format (§6.2.3) | **Tamper-evident audit chain** — SHA-256 hash chain with agent identity, tool name, parameters, result, and timestamp per entry. Implemented in the AgentsID platform. | In production |
| Agent identity (§6.2.4) | **HMAC-SHA256 self-validating tokens** — agents receive tokens that encode identity and delegation chain without requiring a central lookup on every call. | In production |
| Delegation semantics (§6.2.5) | **Scope-narrowing delegation protocol** — parent agents can delegate subsets of their permissions to child agents, with cascading revocation. Children cannot escalate beyond parent scope. | In production |
| Middleware for per-tool permissions (§6.3.2) | **AgentsID Guard** — 50-tool MCP server across 16 categories (shell, files, database, git, HTTP, secrets, containers, cloud). Every tool call validated against per-agent permission rules before execution. | Open-source: npm @agentsid/guard |

All source code, the permission specification, and the scanner are available at **agentsid.dev**. The intent is not to promote a product but to demonstrate that the recommendations in this report are implementable today — and to give the ecosystem a concrete starting point rather than another list of aspirations.

---

*This report was produced by AgentsID Research. Data collected March 29, 2026. For questions, contact research@agentsid.dev.*
