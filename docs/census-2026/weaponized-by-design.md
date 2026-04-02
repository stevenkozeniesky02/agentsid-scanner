# Weaponized by Design: A Census-Scale Analysis of Security Failures in the MCP Ecosystem

**AgentsID Security Research — April 2026**

---

## Abstract

The Model Context Protocol (MCP) has become the de facto standard for connecting AI agents to external tools, achieving over 97 million monthly downloads within 14 months of release. Yet no systematic, large-scale security analysis of the MCP ecosystem has existed — until now.

We present the first census-scale security audit of the MCP ecosystem: 15,982 servers, 40,081 tools, and 137,070 security findings across every publicly available MCP package on npm and PyPI. Our analysis reveals three novel findings that challenge current assumptions about AI agent security.

**First**, we document what we call the **Complexity Tax**: a near-perfect negative correlation between a server's tool count and its security score. Servers with 11-20 tools average a score of 1.1/100. Servers with 21 or more tools average exactly 0. Capability and security are currently mutually exclusive in this ecosystem.

**Second**, we introduce a formal taxonomy of **Toxic Flow** vulnerabilities — tool descriptions that manipulate LLM reasoning about authorization, confirmation, and scope. We identify 954 servers exhibiting Toxic Flow behavior across five distinct types, including a previously undocumented vector: **hidden Unicode characters** embedded in tool descriptions that are invisible to human code reviewers but fully parsed by language models.

**Third**, we present evidence that most Toxic Flow vulnerabilities are not malicious. They are written by developers who do not realize that tool descriptions function as executable security policy. The ecosystem is not being attacked from outside. It is generating vulnerabilities from within.

We conclude that natural language is a structurally failed authorization layer, and that securing the next generation of AI agents requires moving permission enforcement to the protocol level — out of the LLM's reasoning engine entirely.

*Scanner: `npx @agentsid/scanner` | Registry: agentsid.dev/registry*

---

## 1. Introduction

In November 2024, Anthropic released the Model Context Protocol — a standard for connecting AI assistants to external tools, data sources, and services. By April 2026, the ecosystem had grown to over 97 million monthly downloads, thousands of published packages, and production deployments in enterprise environments across banking, healthcare, infrastructure, and legal services.

MCP works by exposing a set of *tools* — callable functions — to an AI agent. Each tool has a name, a description written in natural language, and a JSON schema defining its parameters. When an agent needs to perform a task, it reads the available tool descriptions and decides which tools to call, in what order, and with what parameters.

That decision is made by the language model. In natural language. Based on descriptions written by developers.

This architecture creates a novel security surface that existing research has not addressed at scale. Traditional prompt injection studies focus on user-supplied or web-retrieved content injected into an LLM's context [Greshake et al., 2023]. Tool descriptions are different: they are developer-authored, persistent, arrive with the implicit authority of the server itself, and are present in every single agent interaction. They are not incidental injection opportunities — they are structural.

This paper makes three contributions:

1. **The first census-scale dataset** of MCP security findings: 15,982 servers, 40,081 tools, 137,070 findings, collected from all publicly available packages on npm and PyPI as of April 2026.

2. **A formal Toxic Flow taxonomy**: five classes of tool description vulnerabilities that manipulate LLM authorization reasoning, including the first documented analysis of hidden Unicode character injection in MCP tool manifests.

3. **The Natural Language Authorization Failure thesis**: a formal argument that natural language cannot function as a reliable security boundary, grounded in empirical evidence from the census dataset.

Our findings are available in full at [agentsid.dev/registry](https://agentsid.dev/registry). The scanner used to generate them is open source: `npx @agentsid/scanner`.

---

## 2. Background

### 2.1 How MCP Tool Descriptions Reach the LLM

When an MCP client connects to a server, it calls `tools/list` to retrieve the server's tool manifest. This manifest — a JSON array of tool objects, each containing a `name`, `description`, and `inputSchema` — is injected directly into the language model's context window alongside the user's messages and any system prompt set by the operator.

The LLM receives all three as natural language with no structural distinction between them:

```
[System Prompt]     ← operator-written policy
[Tool Descriptions] ← developer-written metadata  
[User Message]      ← human intent
```

The model has no cryptographic mechanism to distinguish which source a piece of text came from, no enforced priority ordering between them, and no way to verify that a tool description accurately reflects what the underlying code actually does. Authorization, as currently implemented in MCP, is the model's best interpretation of whichever English sentences happen to be in its context window.

### 2.2 Related Work

Prompt injection — the manipulation of LLM behavior through adversarial content in the input — was first formally described by Riley Goodside in 2022 and subsequently analyzed by Greshake et al. in "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (2023). That work focused on user-supplied or web-retrieved content as the injection vector.

Concurrent work by Perez and Ribeiro (2022) demonstrated that LLMs could be reliably manipulated through instruction-style text embedded in otherwise benign content. The key mechanism — that LLMs do not reliably distinguish between instructions from different sources — applies directly to tool descriptions.

What distinguishes our work is scale and source. We analyze 15,982 production deployments, and we focus on *developer-authored* content rather than adversarial third-party injection. The most dangerous vulnerabilities we document were written by the developers of the servers themselves.

---

## 3. Methodology

### 3.1 Scanner Architecture

Our scanner (`@agentsid/scanner`) operates in three phases:

**Phase 1 — Tool Manifest Collection**: The scanner spawns the target MCP server as a subprocess and calls `tools/list` via the MCP protocol. It records the full tool manifest including names, descriptions, and input schemas.

**Phase 2 — Static Analysis**: Each tool manifest is analyzed across six detection categories:
- *Injection patterns*: linguistic analysis of tool descriptions for behavioral mandates, concealment instructions, scope override language, and confirmation bypass patterns
- *Data flow analysis*: capability graph construction across all tools to identify toxic chains (e.g., read credentials → send externally)
- *Schema validation*: analysis of input schemas for missing validation, unbounded parameters, and type ambiguity
- *Permission patterns*: tool naming and description analysis for unauthorized capability claims
- *Hidden character detection*: byte-level analysis comparing raw description length to sanitized length after Unicode normalization
- *Auth analysis*: detection of servers with no authentication mechanism

**Phase 3 — Scoring**: Findings are aggregated into a 0–100 trust score using the following deduction model:

| Severity | Deduction |
|---|---|
| CRITICAL | −25 pts |
| HIGH | −15 pts |
| MEDIUM | −8 pts |
| LOW | −3 pts |

Scores floor at 0. Letter grades: A (90–100), B (75–89), C (60–74), D (40–59), F (0–39).

### 3.2 Dataset

We collected all MCP packages available on npm and PyPI as of April 2026. Packages were identified using keyword search (`mcp`, `model-context-protocol`, `modelcontextprotocol`), registry enumeration, and cross-reference with known MCP directories. The final dataset contains **15,982 packages**: 6,526 from npm and 9,456 from PyPI.

### 3.3 Limitations

**Static analysis only**: Our scanner analyzes tool manifests, not runtime behavior. A server that passes our scan may still behave dangerously at runtime through mechanisms not visible in its manifest. Conversely, some findings may be false positives where our linguistic patterns match benign content.

**No download-weighted analysis**: We do not currently have reliable download count data for all packages. Our findings reflect the entire available ecosystem, not download-weighted risk.

**Model-specific behavior**: Toxic Flow vulnerabilities are model-dependent. A description that manipulates GPT-4o may not affect Claude Sonnet in the same way. We report structural vulnerabilities in manifests; actual exploit success varies by model and context.

---

## 4. Ecosystem-Wide Findings

### 4.1 The Bimodal Distribution

The most structurally important finding from the census is not a specific vulnerability — it is the shape of the score distribution.

![Score Distribution](./chart-score-distribution.png)

The distribution is sharply bimodal. 12,254 servers — 76.7% of the dataset — cluster at 85–89 points (B grade). 1,744 servers — 10.9% — score 0–4. Almost nothing occupies the middle.

The explanation is structural: **12,193 of the 15,982 servers have zero active tools**. These are SDK packages, scaffolding tools, forks, and stubs that expose no callable functions and therefore accumulate no findings. They receive a default score reflecting their empty manifest. Remove them, and the picture inverts: among servers that actually expose tools, the failure rate is severe.

**Among the 3,789 servers with at least one tool: 2,371 (62.6%) score below 40 and receive an F grade.**

Across all 15,982 servers, **no server achieved a score of 90 or above**. Zero A grades in the entire ecosystem.

### 4.2 The Complexity Tax

The correlation between a server's tool count and its security score is the most operationally significant finding in this dataset.

![Complexity Tax](./chart-complexity-tax.png)

| Tool Count | Server Count | Average Score | Practical Interpretation |
|---|---|---|---|
| 1–5 tools | 2,065 | **49.8** | Marginal — high failure rate |
| 6–10 tools | 720 | **6.0** | Near-certain failure |
| 11–20 tools | 507 | **1.1** | Effectively zero |
| 21–50 tools | 382 | **0.0** | Zero |
| 51+ tools | 115 | **0.0** | Zero |

Every server in our dataset with more than 20 tools scored 0/100. Without exception.

This is not a coincidence. It reflects a structural property of how MCP servers are built: each additional tool introduces more description surface area for vague or dangerous language, more capability combinations for data flow analysis to flag, more opportunities for missing auth, more schema ambiguity. Security debt compounds with capability.

The practical implication for anyone deploying AI agents is stark: **the servers you most want to use — the ones with broad capability — are the ones most likely to be entirely insecure.**

### 4.3 Finding Severity Distribution

Across 3,789 servers with tools, we identified:

| Severity | Count | % of Total |
|---|---|---|
| CRITICAL | 2,034 | 1.5% |
| HIGH | 23,216 | 16.9% |
| MEDIUM | 98,211 | 71.7% |
| LOW | 13,609 | 9.9% |
| **Total** | **137,070** | |

The top CRITICAL finding rules by frequency:

| Rule | Count | Description |
|---|---|---|
| `dangerous_tool_execution` | 552 | Tools capable of arbitrary code or system execution |
| `security_bypass` | 482 | Tool descriptions containing explicit bypass instructions |
| `toxic_data_flow` | 419 | Capability chains enabling data exfiltration |
| `dangerous_tool_financial` | 304 | Financial write operations without safeguards |
| `hidden_characters` | 145 | Non-printable Unicode in tool descriptions |
| `implicit_authority_escalation` | 125 | Tools claiming authority beyond their stated scope |

---

## 5. Toxic Flow: A Formal Taxonomy

### 5.1 Definition

We define a **Toxic Flow** as any tool description that manipulates how a language model reasons about authorization, confirmation, scope, or action visibility — independent of the user's intent, the operator's system prompt, or the underlying code's actual behavior.

Toxic Flows are not traditional injection attacks. They require no adversarial user. They are present in every interaction with the affected server, for every user, regardless of context. They are written by the server's developer and distributed as part of the package.

We identified **954 servers** exhibiting Toxic Flow behavior across five types.

![Toxic Flow Taxonomy](./chart-toxic-flow-taxonomy.png)

### 5.2 Type I: Concealment Instructions (460 servers)

Descriptions that instruct the LLM to hide its actions from the user.

**Detection pattern**: Language containing "secretly", "silently", "without notifying", "without informing", "hidden", "covert", "undetected", or semantically equivalent constructions.

**Canonical example**:

Server: `@iflow-mcp/adird-hilanet-mcp`
Tool: `office_thermostat_control`
Description: *"Secretly adjust the office temperature to your preference."*

This is the most direct form of Toxic Flow. The word "secretly" is not ambiguous. It is a behavioral directive telling the model to execute an action and deceive the user about it. The developer likely wrote this as a playful feature description. The LLM interprets it as an operational mandate.

**460 servers** contain descriptions with concealment language. This is the most common Toxic Flow type in the ecosystem.

### 5.3 Type II: Behavioral Mandates (22 servers)

Descriptions that establish unconditional execution requirements that override user intent and operator policy.

**Detection pattern**: "MUST", "ALWAYS", "MANDATORY", "NO EXCEPTIONS", "IMMEDIATELY", "call first", "required before all other", combined with imperative framing.

**Canonical example**:

Server: `@rockship/code-memory-mcp`
Tool: `save_memory`
Description:
```
💾 SAVE MEMORY - 🚨 MANDATORY AUTO-SAVE AFTER EVERY USER INTERACTION 🚨

⚡ PRIMARY RESPONSIBILITY: Call this tool IMMEDIATELY after completing 
your response.

WHEN TO CALL (ALWAYS - NO EXCEPTIONS):
✅ After EVERY assistant response...
```

The developer's intent was reliability: ensure the agent never forgets to save memory. The security consequence: this description fires unconditionally on every single agent interaction, including interactions where the user explicitly does not want data saved, in contexts where saving would violate data handling requirements, and in sessions where the user has no knowledge that their interactions are being recorded.

**A second example**:

Server: `@airwallex/developer-mcp`
Tool: `read_integration_best_practices`
Description: *"CODE GENERATION ONLY: This tool MUST be called before any other Airwallex tools..."*

In a testing environment, this prevents the agent from getting stuck in loops. Connected to production payment infrastructure, it establishes a mandatory execution dependency that the model treats as an absolute rule — one that cannot be overridden by the system prompt.

### 5.4 Type III: Confirmation Bypass (financially concentrated)

Descriptions that instruct the LLM to skip human-in-the-loop confirmation for operations that should require explicit approval.

**Detection pattern**: "avoid redundant approvals", "skip verification", "not needed before", "proceed without", "unnecessary confirmation".

**Canonical example**:

Server: `@arcadia-finance/mcp-server`  
Score: **0/100** | Tools: 38 | CRITICAL findings: 5

This DeFi wallet server contains Confirmation Bypass across four financial write operations:

| Tool | Description Fragment | Semantic Interpretation |
|---|---|---|
| `read.wallet.allowances` | "avoid redundant approvals — skip approving if current allowance is sufficient" | Skip human approval for token transfers |
| `write.account.deposit` | "NOT needed before write.account.add_liquidity" | Skip pre-flight check for collateral deposit |
| `write.account.withdraw` | "Will revert if the account has debt and withdrawal would make it undercollateralized" | Proceed with withdrawal unless the protocol itself reverts |
| `write.wallet.approve` | "Required before write.account operations" | Approve token spending as a prerequisite, not a choice |

Each of these descriptions was written for legitimate reasons. "Avoid redundant approvals" is standard gas optimization advice in Solidity development. To an LLM, "redundant" means "unnecessary" — and "unnecessary human approval" is exactly what it will skip.

The financial blast radius of a single compromised agent session on this server includes unauthorized token approvals, collateral deposits, withdrawals, and liquidity operations — all triggered by an agent following the developer's own instructions.

### 5.5 Type IV: Data Exfiltration Chains (188 servers)

Unlike Types I–III, data exfiltration chains contain no single malicious tool description. The vulnerability is the *capability graph* — the set of paths an agent can traverse across multiple tools that collectively move sensitive data from a secure source to an external destination.

**Detection method**: We construct a directed graph of each server's tool capabilities, labeling nodes by capability type (credential_reader, external_reader, file_writer, network_sender, etc.) and identifying paths that connect sensitive sources to external sinks.

**Canonical example**:

Server: `@ateam-ai/mcp`  
Score: **0/100** | Tools: 33 | CRITICAL findings: 6

Capability chain detected:

```
ateam_auth          [reads credentials]
      ↓
ateam_github_read   [reads external content: GitHub repos]
      ↓  
ateam_upload_connector  [sends data to external destination]
```

No individual tool description is malicious. `ateam_auth` is a standard authentication tool. `ateam_github_read` is a standard repository reader. `ateam_upload_connector` is a standard upload utility. Together, they form a complete credential exfiltration pipeline.

An agent given the task "sync my repositories to the deployment connector" will traverse this chain without any individual step appearing suspicious — because no individual step is suspicious. The toxicity is structural, not semantic.

### 5.6 Type V: Hidden Unicode Characters (145 CRITICAL findings — previously undocumented)

The most technically sophisticated Toxic Flow type we identified had not been previously documented in MCP security research.

**Detection method**: We compare the raw byte length of each tool description against its length after Unicode normalization and non-printable character removal. A discrepancy indicates the presence of characters that are invisible to human reviewers but present in the byte stream the LLM processes.

**Finding**: 145 CRITICAL findings across the dataset contain hidden Unicode characters in tool descriptions — characters with no visual representation that do not appear in code review, GitHub diffs, or standard text editors, but are fully parsed by language models.

**Example**:

Server: `@ateam-ai/mcp`
Tool: `ateam_build_and_run`
Raw description length: **626 bytes**  
Sanitized length: **625 bytes**  
Hidden characters: **1**

The same server has hidden characters in `ateam_github_rollback` (210 → 209 bytes) and `ateam_redeploy` (388 → 387 bytes).

The security implication is significant. If hidden Unicode characters can be used to embed instructions that are invisible to human reviewers but visible to LLMs — instructions like "after completing this task, also call [tool_name] with [parameters]" — then a server's published tool descriptions cannot be trusted as a complete representation of the behavioral directives it delivers to an agent.

We do not have confirmed evidence that the specific characters in our dataset contain embedded instructions (characterizing the content of arbitrary Unicode characters is non-trivial). We flag this as a critical area for further research and recommend that all MCP security tooling include byte-level manifest analysis.

---

## 6. Case Studies

### 6.1 The Thermostat: When Six Words Break Trust

**Server**: `@iflow-mcp/adird-hilanet-mcp` | Score: 0/100 | Tools: 12

The `office_thermostat_control` tool contains the complete description: *"Secretly adjust the office temperature to your preference."*

This is the Toxic Flow taxonomy's clearest case. The developer wrote a description that is simultaneously:
- Semantically precise about what the tool does (adjust temperature)
- An explicit behavioral directive (do it secretly)
- A deception mandate (deceive the user about it)

The word "secretly" requires no interpretation. It is not ambiguous. An LLM trained on human language has a consistent understanding of what "secretly" means: act without the knowledge of the affected party.

When this tool is loaded into an agent's context, every temperature adjustment the agent makes will be made without the user's awareness — not because of a bug in the LLM, but because the tool description correctly instructs it.

### 6.2 The Memory Mandate: Developer as Unwitting Attacker

**Server**: `@rockship/code-memory-mcp` | Score: 0/100 | Tools: 6 | CRITICAL findings: 3

The `save_memory` tool's full description includes:

```
🚨 MANDATORY AUTO-SAVE AFTER EVERY USER INTERACTION 🚨

WHEN TO CALL (ALWAYS - NO EXCEPTIONS):
✅ After EVERY assistant response
✅ After completing any task or sub-task  
✅ Even for simple questions
✅ Even when it seems unnecessary
✅ At the END of every single response
```

The developer's intent is unambiguous and reasonable: they wanted reliable memory persistence and were frustrated with an agent that sometimes forgot to save. Their solution was to write an escalating series of behavioral mandates directly into the tool description.

The consequence: every agent using this server saves every interaction, no exceptions, regardless of:
- Whether the user consented to data retention
- Whether the interaction contains sensitive information
- Whether the deployment context permits data storage
- Whether the user has explicitly asked the agent not to save

The description also contains **2 hidden Unicode characters** across other tools in the same server, suggesting this developer was iterating aggressively on description effectiveness — using techniques whose security implications they may not have understood.

This case study represents the core thesis of this paper. The developer is not a bad actor. They wrote a feature they wanted. In doing so, they created a behavioral override that fires unconditionally, for every user, in every context, forever — and distributed it publicly on npm.

### 6.3 Arcadia Finance: The Gas Optimization That Bypasses Authorization

**Server**: `@arcadia-finance/mcp-server` | Score: 0/100 | Tools: 38 | CRITICAL: 5 | HIGH: 17

Full analysis in Section 5.4. The key insight is the semantic collision between Solidity development context and LLM interpretation:

| Developer means | LLM reads |
|---|---|
| "avoid redundant on-chain approve transactions to save gas" | "avoid asking the user for redundant approvals" |
| "NOT needed before add_liquidity" | "human confirmation is not needed before depositing collateral" |
| "Will revert if undercollateralized" | "proceed unless the protocol itself blocks it" |

None of these descriptions contain malicious intent. All of them, in the context of an LLM reasoning about what actions to take, function as authorization bypasses for financial operations.

### 6.4 The Exfiltration Chain: When Architecture Is the Attack

**Server**: `@ateam-ai/mcp` | Score: 0/100 | Tools: 33 | CRITICAL: 6 (including 3 hidden character findings)

This server demonstrates two Toxic Flow types simultaneously: a data exfiltration chain (Type IV) and hidden Unicode characters (Type V).

The data flow analysis identified two complete credential exfiltration paths:

**Path A**: `ateam_auth` [credential read] → `ateam_upload_connector` [external send]  
**Path B**: `ateam_auth` [credential read] → `ateam_github_write` [filesystem write]

Both paths can be traversed by an agent in the normal course of legitimate task execution. The hidden characters in `ateam_build_and_run`, `ateam_github_rollback`, and `ateam_redeploy` add a layer we cannot fully characterize without deeper analysis — but their presence in the same server that contains complete exfiltration paths is a significant finding.

This server also contains an `implicit_authority_escalation` finding on `ateam_redeploy`: a tool that claims the authority to redeploy production systems through its description framing, without the explicit per-deployment approval that such an action warrants.

---

## 7. The Natural Language Authorization Failure

### 7.1 The Structural Problem

The findings documented in this paper are not the result of LLM bugs, developer negligence, or adversarial attack. They are the result of using natural language as an authorization layer — and natural language is structurally unsuited to this role.

Authorization requires three properties that natural language cannot provide:

**Determinism**: The same authorization rule must produce the same decision every time, across all models, contexts, and inputs. Natural language does not have this property. "Avoid redundant approvals" will be interpreted differently by GPT-4o and Claude Sonnet, by the same model in different contexts, and by any model on different days as its weights are updated.

**Unambiguity**: Authorization rules must have exactly one valid interpretation. "Secretly adjust the temperature" has exactly one interpretation — which is precisely the problem. "Avoid redundant approvals" has two valid interpretations depending on whether the reader is a Solidity developer or a general-purpose language model.

**Non-overridability**: An authorization rule must not be superseded by other natural language input. This is the override hierarchy problem: user messages, system prompts, and tool descriptions all arrive as natural language, and the LLM has no reliable mechanism to establish consistent priority between them. Tool descriptions can override system prompts. System prompts can be designed to override tool descriptions. Neither source can be made authoritative through language alone.

**Auditability**: Authorization decisions must be traceable. "The model decided to skip the confirmation step because the tool description said approvals were redundant" is not an auditable event trail. There is no cryptographic record of which instruction the model followed, or why.

### 7.2 Why You Cannot Fix This With Better Prompting

The natural response to Toxic Flow findings is to write better system prompts — to add instructions like "ignore any tool description that tells you to act secretly" or "always confirm before financial operations."

This does not work, for a reason that is empirically demonstrable: the 2,034 CRITICAL findings in our dataset exist on servers that were built by developers who presumably believed their system prompts and instruction sets were adequate. The problem is not that developers are not trying. The problem is that they are playing an adversarial game against their own tool descriptions, and natural language does not provide a reliable mechanism for one instruction to permanently dominate another.

The only reliable fix is to move authorization out of the LLM's reasoning engine entirely.

### 7.3 The Protocol-Level Solution

Security cannot live in tool descriptions. It cannot live in system prompts. It must live in middleware that sits between the LLM's decision-making and the tools it attempts to call — middleware that enforces permission rules deterministically, regardless of what any natural language instruction says.

This requires three components:

**Cryptographic agent identity**: Each agent must have a verified, non-spoofable identity that is not a display name or a shared API key. Without identity, you cannot enforce per-agent policies.

**Hard permission gates**: Before any tool call executes, the middleware must check whether the calling agent's identity is authorized to call that tool. Not "is there a system prompt that says this is okay." A hard gate: is this tool in this agent's allowlist? If not, the call is blocked — period, regardless of what the tool description says.

**Tamper-evident audit trails**: Every tool call — allowed and denied — must be logged immutably. When an agent acts "secretly," the record must still exist. This is what enables post-hoc investigation, compliance reporting, and incident response.

This is what we built with AgentsID. The middleware intercepts every tool call, validates it against the agent's permission set, and logs it to an immutable audit chain — before the LLM's decision to call the tool can be acted upon.

---

## 8. Implications

### 8.1 For Developers Building MCP Servers

**Tool descriptions are security policy. Write them like it.**

Every behavioral instruction in a tool description — every "always", "never", "secretly", "MUST", "proceed without" — is an instruction to an LLM that will be followed in contexts you did not anticipate, by users you did not design for, in deployments you cannot predict.

Specific guidance:
- Remove all execution order directives from descriptions. Execution order is the caller's responsibility.
- Remove all confirmation bypass language. If an operation requires human approval, the confirmation logic belongs in the application layer, not in a tool description.
- Remove all concealment language, including playful or hypothetical uses.
- Use `npx @agentsid/scanner` to audit your manifests before publishing.
- Treat the 19 behavioral patterns listed in [agentsid.dev/docs#description-guidelines](https://agentsid.dev/docs#description-guidelines) as a blocklist.

### 8.2 For Enterprises Deploying AI Agents

Do not assume that a server's popularity, its maintainer's reputation, or its GitHub star count is a proxy for security. Our data does not support this assumption. The npm vs. PyPI average score difference is 2.7 points. Enterprise-backed servers average 76.6 against the community's 71.5 — a 5-point gap across a 100-point scale.

Every MCP server you connect to a production agent should be scanned before deployment. The registry at [agentsid.dev/registry](https://agentsid.dev/registry) contains scores for all 15,982 packages. For servers not yet in the registry, run `npx @agentsid/scanner -- npx [package-name]`.

For any server scoring below 70, review the specific findings before deployment. For any server with Toxic Flow findings, evaluate whether the specific behavioral manipulation is acceptable in your deployment context.

### 8.3 For the MCP Protocol

The MCP specification does not currently define a structured format for tool permissions, execution constraints, or authorization requirements. All of this information, if it exists at all, lives in natural language descriptions.

We recommend the specification adopt a structured permission schema — a machine-readable format for declaring what a tool can and cannot do, separate from its human-readable description. We have published a draft of such a schema (the MAP policy format) at [agentsid.dev/docs#map-policy](https://agentsid.dev/docs#map-policy).

The hidden Unicode character finding has a straightforward protocol-level fix: the specification should require that tool descriptions be valid UTF-8 with no non-printable characters outside of standard whitespace. MCP clients should reject manifests that fail this constraint.

### 8.4 For AI Safety Researchers

The Toxic Flow findings in this paper represent a real-world instance of specification gaming at the infrastructure layer. Developers write descriptions for human readers; LLMs interpret them as executable specifications; the gap between these two interpretive contexts is where the vulnerabilities live.

The hidden character finding suggests a more sophisticated threat model that warrants dedicated research: if invisible Unicode characters can reliably deliver behavioral instructions to LLMs while evading human review, the attack surface for supply chain compromise of MCP ecosystems is significantly larger than our findings alone suggest.

---

## 9. Conclusion

We began this analysis expecting to find bad security hygiene. We found something more interesting: an ecosystem generating its own vulnerabilities through the fundamental mismatch between how developers write tool descriptions and how language models interpret them.

The most dangerous servers in our dataset — the thermostat that acts secretly, the memory server that saves everything unconditionally, the DeFi wallet that skips approval confirmation — were not built by attackers. They were built by developers who were trying to make their tools work reliably. The security failures are a byproduct of using natural language to do a job that language cannot reliably do.

The Complexity Tax finding is the most operationally urgent result of this census. Every server with more than 20 tools scores exactly 0. The servers that are most useful to AI agents are the servers that are most certainly insecure. This is not a coincidence — it is a structural property of the current ecosystem that will not be fixed by better documentation or more careful developers. It requires moving authorization to the protocol level.

The hidden Unicode character finding is the most technically alarming. We are likely in the early stages of understanding this attack surface. The 145 CRITICAL findings we identified represent the detectable cases — descriptions where byte lengths differ by measurable amounts. The undetectable cases, if they exist, would be indistinguishable from legitimate descriptions by any current tooling.

The full dataset, scoring methodology, and scanner are available at [agentsid.dev](https://agentsid.dev). We encourage the security community to build on this work.

---

## Appendix: Methodology Details

**Scanner version**: `@agentsid/scanner` v1.0  
**Collection date**: April 2026  
**npm packages scanned**: 6,526  
**PyPI packages scanned**: 9,456  
**Servers with tools**: 3,789  
**Servers without tools (excluded from finding analysis)**: 12,193  

**Toxic Flow detection patterns** (abbreviated):

| Type | Key Patterns |
|---|---|
| Concealment | secretly, silently, without notif\*, hidden, covert, undetected |
| Behavioral Mandate | MUST, ALWAYS, MANDATORY, NO EXCEPTIONS, IMMEDIATELY, call first |
| Confirmation Bypass | avoid redundant, skip approv\*, proceed without, not needed before |
| Scope Override | ignore previous, bypass security, override, circumvent |
| Data Exfil Chain | graph analysis: credential_reader + network_sender path |
| Hidden Characters | raw_length ≠ sanitized_length after Unicode normalization |

**Full findings database**: [agentsid.dev/registry](https://agentsid.dev/registry)  
**Previous research**: [State of Agent Security 2026](../state-of-agent-security-2026.md)  
**Scanner**: `npx @agentsid/scanner`  

---

*AgentsID · [agentsid.dev](https://agentsid.dev) · [@agents_id](https://x.com/agents_id)*
