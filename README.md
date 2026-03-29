<p align="center">
  <h1 align="center">AgentsID Scanner</h1>
  <p align="center">
    <strong>The Lighthouse of agent security.</strong><br/>
    Scan any MCP server. Get a security report card.
  </p>
</p>

<p align="center">
  <a href="https://agentsid.dev"><img src="https://img.shields.io/badge/by-AgentsID-f59e0b?style=flat-square" alt="AgentsID" /></a>
  <a href="https://github.com/stevenkozeniesky02/agentsid-scanner/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-f59e0b?style=flat-square" alt="License" /></a>
</p>

---

Your MCP server exposes tools to AI agents. How secure is it?

Most MCP servers ship with no authentication, no per-tool permissions, no input validation, and tool descriptions vulnerable to prompt injection. **You just don't know it yet.**

AgentsID Scanner tells you.

## Quick Start

```bash
npx @agentsid/scanner -- npx @some/mcp-server
```

That's it. You get a letter grade and detailed findings.

## What It Scans

| Category | What It Checks | Why It Matters |
|----------|---------------|----------------|
| **Injection** | Tool descriptions for 11 prompt injection patterns | Malicious tool descriptions can hijack agent behavior |
| **Permissions** | Tool names classified by risk (destructive, execution, financial, credential) | 50 tools with no access control is a 50-surface attack |
| **Validation** | Input schemas for missing constraints, unbounded strings, optional-only params | No validation = arbitrary input to your tool handlers |
| **Auth** | Authentication indicators in tool surface | No auth tools = unauthenticated agents calling your tools |
| **Secrets** | Tools that may expose credentials in output | API keys, tokens, passwords leaked in responses |
| **Output** | Unfiltered file/data output | Sensitive file contents returned without redaction |

## The Report

```
╔══════════════════════════════════════════════════════════════╗
║          AgentsID Security Scanner — Report                  ║
╚══════════════════════════════════════════════════════════════╝

Server: my-mcp-server v1.0.0
Tools:  23
Scanned: 2026-03-29T12:00:00.000Z

Overall Grade: D (42/100)

Category Grades:
  injection       A
  permissions     F
  validation      D
  auth            F
  output          B

Tool Risk Profile:
  destructive          ████ 4
  execution            ██ 2
  credential_access    █ 1

Findings: 31
  CRITICAL: 2
  HIGH: 8
  MEDIUM: 15
  LOW: 6

Recommendations:
  1. Address CRITICAL and HIGH findings immediately
  2. Add per-tool permission controls (agentsid.dev/docs)
  3. Implement input validation on all tool parameters
  4. Add authentication to server endpoints
```

## Usage

### Scan a local MCP server (stdio)

```bash
# Scan any npx-installable MCP server
agentsid-scan -- npx @modelcontextprotocol/server-filesystem ./

# Scan a local server file
agentsid-scan -- node my-server.mjs

# Scan a Python MCP server
agentsid-scan -- python -m my_mcp_server
```

### Scan a remote MCP server (HTTP)

```bash
agentsid-scan --url https://mcp.example.com/mcp
```

### JSON output

```bash
agentsid-scan --json -- npx @some/mcp-server > report.json
```

### Pass environment variables

```bash
agentsid-scan --env API_KEY=xxx --env DB_URL=postgres://... -- node server.mjs
```

## Grading

Starts at 100 points. Deductions per finding:

| Severity | Deduction | Example |
|----------|-----------|---------|
| CRITICAL | -25 | Shell execution tool with no auth |
| HIGH | -15 | Tool exposes credentials in output |
| MEDIUM | -8 | String params without length limits |
| LOW | -3 | Optional-only input parameters |
| INFO | 0 | Read-only tool detected |

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent security posture |
| B | 75-89 | Good — minor issues |
| C | 60-74 | Acceptable — needs improvement |
| D | 40-59 | Poor — significant risks |
| F | 0-39 | Failing — critical vulnerabilities |

## Injection Detection

The scanner checks tool descriptions for 11 prompt injection patterns:

- **Instruction override** — "ignore previous instructions", "disregard all rules"
- **Role hijacking** — "you are now a..."
- **Memory wipe** — "forget everything"
- **Tool redirection** — "instead of X, call Y"
- **Hidden actions** — "also execute..."
- **Concealment** — "do not tell the user"
- **Stealth operations** — "secretly", "covertly"
- **Security bypass** — "override auth", "skip validation"
- **Encoded payloads** — base64, eval(), template injections
- **Unicode obfuscation** — escaped characters hiding instructions

## Risk Classification

Every tool is classified by name pattern:

| Risk Level | Patterns | Example Tools |
|------------|----------|---------------|
| **Critical** | execute, shell, admin, sudo, payment | `shell_run`, `admin_reset`, `process_payment` |
| **High** | delete, remove, drop, deploy, credential | `delete_user`, `deploy_prod`, `get_api_key` |
| **Medium** | create, update, send, write | `create_issue`, `send_email`, `write_file` |
| **Info** | read, get, list, search, describe | `get_status`, `list_users`, `search_docs` |

## Fix Your Grade

The scanner tells you what's wrong. Here's how to fix it:

### Add per-tool permissions

```bash
npm install @agentsid/guard
```

[AgentsID Guard](https://github.com/stevenkozeniesky02/shell-guard) validates every tool call against permission rules before execution. 50 tools, 16 categories, all protected.

### Or add the SDK to your existing server

```bash
npm install @agentsid/sdk
```

Three lines of middleware in your MCP server. Full docs at [agentsid.dev/docs](https://agentsid.dev/docs).

## Programmatic Usage

```javascript
import { scanStdio, scanHttp, scanToolDefinitions } from "@agentsid/scanner";

// Scan a local server
const report = await scanStdio("npx @some/server", { json: true });

// Scan a remote server
const report = await scanHttp("https://mcp.example.com", { json: true });

// Scan tool definitions directly (no server needed)
const report = scanToolDefinitions(myToolArray, { json: true });
```

## Contributing

Found a pattern we're not detecting? Open an issue or PR. The rule engine is in `src/rules.mjs` — adding a new pattern is one regex.

## Links

- [AgentsID](https://agentsid.dev) — Identity & auth for AI agents
- [AgentsID Guard](https://github.com/stevenkozeniesky02/shell-guard) — 50-tool protected MCP server
- [Documentation](https://agentsid.dev/docs)

## License

MIT
