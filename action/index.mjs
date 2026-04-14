/**
 * AgentsID Security Scanner — GitHub Action
 *
 * Runs on every PR to an MCP server repo. Scans tool definitions,
 * grades security posture, and comments on the PR with findings.
 *
 * Three scan modes:
 * 1. server-command: Start an MCP server via stdio and enumerate tools
 * 2. server-url: Connect to a remote MCP server via HTTP
 * 3. tool-definitions: Static analysis of a JSON file with tool definitions
 */

import * as core from "@actions/core";
import * as github from "@actions/github";
import { scanStdio, scanHttp, scanToolDefinitions } from "../src/scanner.mjs";
import { readFileSync } from "fs";

async function run() {
  try {
    const serverCommand = core.getInput("server-command");
    const serverUrl = core.getInput("server-url");
    const toolDefsPath = core.getInput("tool-definitions");
    const failOn = core.getInput("fail-on").toUpperCase();
    const shouldComment = core.getInput("comment") === "true";

    let reportJson;

    // ── Scan ──
    if (serverCommand) {
      core.info(`Scanning MCP server: ${serverCommand}`);
      reportJson = await scanStdio(serverCommand, { json: true, timeout: 60000 });
    } else if (serverUrl) {
      core.info(`Scanning remote MCP server: ${serverUrl}`);
      reportJson = await scanHttp(serverUrl, { json: true, timeout: 30000 });
    } else if (toolDefsPath) {
      core.info(`Scanning tool definitions: ${toolDefsPath}`);
      const tools = JSON.parse(readFileSync(toolDefsPath, "utf-8"));
      const toolArray = Array.isArray(tools) ? tools : tools.tools || [];
      reportJson = scanToolDefinitions(toolArray, { json: true, serverName: toolDefsPath });
    } else {
      // Auto-detect: look for common MCP tool definition files
      const autoFiles = [
        "tools.json",
        "mcp-tools.json",
        "src/tools.json",
        ".mcp/tools.json",
      ];

      let found = false;
      for (const f of autoFiles) {
        try {
          const content = readFileSync(f, "utf-8");
          const tools = JSON.parse(content);
          const toolArray = Array.isArray(tools) ? tools : tools.tools || [];
          if (toolArray.length > 0) {
            core.info(`Auto-detected tool definitions: ${f}`);
            reportJson = scanToolDefinitions(toolArray, { json: true, serverName: f });
            found = true;
            break;
          }
        } catch {}
      }

      if (!found) {
        core.warning("No scan target specified. Use server-command, server-url, or tool-definitions input.");
        return;
      }
    }

    const report = JSON.parse(reportJson);

    // ── Set Outputs ──
    core.setOutput("grade", report.grade.overall);
    core.setOutput("score", report.grade.score);
    core.setOutput("findings", report.findings.length);
    core.setOutput("critical", report.summary.CRITICAL || 0);
    core.setOutput("report", reportJson);

    // ── Log Summary ──
    core.info(`Grade: ${report.grade.overall} (${report.grade.score}/100)`);
    core.info(`Tools: ${report.toolCount}`);
    core.info(`Findings: ${report.findings.length} (${report.summary.CRITICAL || 0} critical, ${report.summary.HIGH || 0} high)`);

    // ── PR Comment ──
    if (shouldComment && github.context.payload.pull_request) {
      const token = process.env.GITHUB_TOKEN;
      if (token) {
        const octokit = github.getOctokit(token);
        const { owner, repo } = github.context.repo;
        const prNumber = github.context.payload.pull_request.number;

        const gradeEmoji = {
          A: "🟢", B: "🟢", C: "🟡", D: "🔴", F: "🔴"
        }[report.grade.overall] || "⚪";

        // Build category grades table
        const catRows = Object.entries(report.grade.categories || {})
          .map(([cat, g]) => `| ${cat} | ${g} |`)
          .join("\n");

        // Build critical/high findings list
        const criticalFindings = report.findings
          .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
          .slice(0, 10)
          .map((f) => `- **${f.severity}**: ${f.detail}${f.tool && f.tool !== "*" ? ` (\`${f.tool}\`)` : ""}`)
          .join("\n");

        const commentBody = `## ${gradeEmoji} AgentsID Security Scan: **${report.grade.overall}** (${report.grade.score}/100)

| Metric | Value |
|--------|-------|
| Tools scanned | ${report.toolCount} |
| Total findings | ${report.findings.length} |
| Critical | ${report.summary.CRITICAL || 0} |
| High | ${report.summary.HIGH || 0} |
| Medium | ${report.summary.MEDIUM || 0} |
| Low | ${report.summary.LOW || 0} |

### Category Grades

| Category | Grade |
|----------|-------|
${catRows}

${criticalFindings ? `### Critical & High Findings\n\n${criticalFindings}` : "### No critical or high findings 🎉"}

${report.grade.score < 60 ? `### Recommendations

1. Add per-tool permission controls — [AgentsID Docs](https://agentsid.dev/docs)
2. Implement input validation on tool parameters
3. Add authentication to server endpoints
4. Use [AgentsID Guard](https://github.com/AgentsID-dev/shell-guard) for built-in protection` : ""}

---
<sub>Scanned by [AgentsID Security Scanner](https://github.com/AgentsID-dev/agentsid-scanner) · [Fix your grade](https://agentsid.dev/docs)</sub>`;

        // Check for existing comment and update it
        const { data: comments } = await octokit.rest.issues.listComments({
          owner, repo, issue_number: prNumber,
        });

        const existingComment = comments.find(
          (c) => c.body?.includes("AgentsID Security Scan")
        );

        if (existingComment) {
          await octokit.rest.issues.updateComment({
            owner, repo, comment_id: existingComment.id, body: commentBody,
          });
          core.info("Updated existing PR comment");
        } else {
          await octokit.rest.issues.createComment({
            owner, repo, issue_number: prNumber, body: commentBody,
          });
          core.info("Posted PR comment");
        }
      } else {
        core.warning("GITHUB_TOKEN not set — cannot post PR comment");
      }
    }

    // ── Fail Check ──
    if (failOn) {
      const gradeOrder = { A: 5, B: 4, C: 3, D: 2, F: 1 };
      const currentGrade = gradeOrder[report.grade.overall] || 0;
      const requiredGrade = gradeOrder[failOn] || 0;

      if (currentGrade < requiredGrade) {
        core.setFailed(
          `Security grade ${report.grade.overall} (${report.grade.score}/100) is below required grade ${failOn}`
        );
      }
    }
  } catch (err) {
    core.setFailed(`Scanner failed: ${err.message}`);
  }
}

run();
