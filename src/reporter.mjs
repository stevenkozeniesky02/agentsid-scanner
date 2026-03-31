/**
 * Report generator — formats scan results into human-readable output.
 * Supports terminal (ANSI colors) and JSON output.
 */

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
};

const SEVERITY_COLORS = {
  CRITICAL: COLORS.bgRed + COLORS.white,
  HIGH: COLORS.red,
  MEDIUM: COLORS.yellow,
  LOW: COLORS.cyan,
  INFO: COLORS.dim,
};

const GRADE_COLORS = {
  A: COLORS.green,
  B: COLORS.green,
  C: COLORS.yellow,
  D: COLORS.red,
  F: COLORS.bgRed + COLORS.white,
};

function severityBadge(sev) {
  return `${SEVERITY_COLORS[sev] || ""}${sev}${COLORS.reset}`;
}

function gradeBadge(letter, score) {
  return `${GRADE_COLORS[letter] || ""}${COLORS.bold}${letter} (${score}/100)${COLORS.reset}`;
}

export function formatTerminalReport(serverInfo, tools, findings, gradeResult, riskProfile, mapPolicy) {
  const lines = [];
  const { bold, dim, reset, cyan, yellow, green, red } = COLORS;

  // Header
  lines.push("");
  lines.push(`${bold}╔══════════════════════════════════════════════════════════════╗${reset}`);
  lines.push(`${bold}║          AgentsID Security Scanner — Report                  ║${reset}`);
  lines.push(`${bold}╚══════════════════════════════════════════════════════════════╝${reset}`);
  lines.push("");

  // Server info
  lines.push(`${bold}Server:${reset} ${serverInfo.name || "unknown"} v${serverInfo.version || "?"}`);
  lines.push(`${bold}Tools:${reset}  ${tools.length}`);
  lines.push(`${bold}Scanned:${reset} ${new Date().toISOString()}`);
  lines.push("");

  // Overall grade
  lines.push(`${bold}Overall Grade: ${gradeBadge(gradeResult.letter, gradeResult.score)}${reset}`);
  lines.push("");

  // Category grades
  lines.push(`${bold}Category Grades:${reset}`);
  for (const [cat, letter] of Object.entries(gradeResult.categoryGrades)) {
    const color = GRADE_COLORS[letter] || "";
    lines.push(`  ${cat.padEnd(15)} ${color}${letter}${reset}`);
  }
  lines.push("");

  // Risk profile
  if (riskProfile) {
    lines.push(`${bold}Tool Risk Profile:${reset}`);
    const riskEntries = Object.entries(riskProfile).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
    for (const [risk, count] of riskEntries) {
      const bar = "█".repeat(Math.min(count, 30));
      const riskColor = ["destructive", "execution", "privilege", "financial"].includes(risk) ? red : yellow;
      lines.push(`  ${risk.padEnd(20)} ${riskColor}${bar}${reset} ${count}`);
    }
    if (riskEntries.length === 0) lines.push(`  ${dim}(no high-risk tools detected)${reset}`);
    lines.push("");
  }

  // Finding summary
  lines.push(`${bold}Findings: ${gradeResult.totalFindings}${reset}`);
  if (gradeResult.critical > 0) lines.push(`  ${SEVERITY_COLORS.CRITICAL} CRITICAL: ${gradeResult.critical} ${reset}`);
  if (gradeResult.high > 0) lines.push(`  ${SEVERITY_COLORS.HIGH}HIGH: ${gradeResult.counts.HIGH}${reset}`);
  if (gradeResult.counts.MEDIUM > 0) lines.push(`  ${SEVERITY_COLORS.MEDIUM}MEDIUM: ${gradeResult.counts.MEDIUM}${reset}`);
  if (gradeResult.counts.LOW > 0) lines.push(`  ${SEVERITY_COLORS.LOW}LOW: ${gradeResult.counts.LOW}${reset}`);
  lines.push("");

  // Detailed findings
  if (findings.length > 0) {
    lines.push(`${bold}Detailed Findings:${reset}`);
    lines.push(`${"─".repeat(62)}`);

    // Group by category
    const grouped = {};
    for (const f of findings) {
      const cat = f.category || "other";
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(f);
    }

    for (const [cat, catFindings] of Object.entries(grouped).sort()) {
      lines.push(`\n${bold}${cyan}[${cat.toUpperCase()}]${reset}`);
      for (const f of catFindings) {
        lines.push(`  ${severityBadge(f.severity)} ${f.detail}`);
        if (f.tool && f.tool !== "*") lines.push(`    ${dim}Tool: ${f.tool}${reset}`);
        if (f.evidence) lines.push(`    ${dim}Evidence: ${f.evidence.substring(0, 100)}...${reset}`);
      }
    }
    lines.push("");
  }

  // Recommendations
  lines.push(`${bold}Recommendations:${reset}`);
  if (gradeResult.critical > 0 || gradeResult.high > 0) {
    lines.push(`  ${red}1. Address CRITICAL and HIGH findings immediately${reset}`);
    lines.push(`  ${yellow}2. Add per-tool permission controls (agentsid.dev/docs)${reset}`);
    lines.push(`  3. Implement input validation on all tool parameters`);
    lines.push(`  4. Add authentication to server endpoints`);
  } else if (gradeResult.counts.MEDIUM > 0) {
    lines.push(`  ${green}Good security posture.${reset} Address MEDIUM findings for improvement:`);
    lines.push(`  1. Tighten input validation schemas`);
    lines.push(`  2. Consider per-agent tool scoping`);
  } else {
    lines.push(`  ${green}Excellent security posture.${reset} No significant issues found.`);
  }

  // MAP policy block
  if (mapPolicy) {
    lines.push(`${bold}Generated agentsid.json Policy:${reset}`);
    lines.push(`${"─".repeat(62)}`);
    lines.push(JSON.stringify(mapPolicy, null, 2));
    lines.push("");
    lines.push(`${dim}→ Written to agentsid.json — deploy with: npx @agentsid/guard${reset}`);
    lines.push("");
  }

  lines.push(`${dim}Scan powered by AgentsID — agentsid.dev/scanner${reset}`);
  lines.push(`${dim}Protect this server with per-agent permissions: npx @agentsid/guard${reset}`);
  lines.push("");

  return lines.join("\n");
}

export function formatHtmlReport(serverInfo, tools, findings, gradeResult, riskProfile, mapPolicy) {
  const scannedAt = new Date().toISOString();

  const SEVERITY_COLORS = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#2563eb", INFO: "#6b7280" };
  const GRADE_COLORS = { A: "#16a34a", B: "#16a34a", C: "#ca8a04", D: "#ea580c", F: "#dc2626" };

  const severityBadge = (sev) =>
    `<span style="background:${SEVERITY_COLORS[sev] || "#6b7280"};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700">${sev}</span>`;

  // Group findings by category
  const grouped = {};
  for (const f of findings) {
    const cat = f.category || "other";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(f);
  }

  const findingRows = Object.entries(grouped).sort().map(([cat, catFindings]) => {
    const rows = catFindings.map((f) => `
      <tr>
        <td style="padding:8px 12px;vertical-align:top">${severityBadge(f.severity)}</td>
        <td style="padding:8px 12px;vertical-align:top;font-size:13px">${f.detail}</td>
        <td style="padding:8px 12px;vertical-align:top;font-size:12px;color:#6b7280;font-family:monospace">${f.tool && f.tool !== "*" ? f.tool : ""}</td>
        <td style="padding:8px 12px;vertical-align:top;font-size:12px;color:#ef4444;font-weight:600;font-family:monospace">${f.evidence ? `<strong>${f.evidence}</strong>` : ""}</td>
      </tr>`).join("");
    return `
      <tr><td colspan="4" style="padding:12px 12px 4px;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#374151;background:#f9fafb;border-top:2px solid #e5e7eb">${cat}</td></tr>
      ${rows}`;
  }).join("");

  const categoryBadges = Object.entries(gradeResult.categoryGrades || {}).map(([cat, letter]) =>
    `<span style="display:inline-block;margin:3px;padding:4px 10px;border-radius:4px;font-size:12px;font-weight:700;background:#f3f4f6;color:${GRADE_COLORS[letter] || "#374151"}">${cat}: ${letter}</span>`
  ).join("");

  const riskTags = Object.entries(riskProfile || {}).filter(([, v]) => v > 0).map(([risk, count]) =>
    `<span style="display:inline-block;margin:3px;padding:3px 8px;border-radius:4px;font-size:11px;background:#fef3c7;color:#92400e">${risk} ×${count}</span>`
  ).join("");

  const policyBlock = mapPolicy
    ? `<div style="margin-top:32px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <h2 style="margin:0;font-size:16px;font-weight:700">Generated agentsid.json Policy</h2>
          <button onclick="navigator.clipboard.writeText(document.getElementById('policy-block').textContent)" style="padding:4px 12px;font-size:12px;border:1px solid #d1d5db;border-radius:4px;cursor:pointer;background:#fff">Copy</button>
        </div>
        <pre id="policy-block" style="background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;overflow-x:auto;font-size:12px;line-height:1.6">${JSON.stringify(mapPolicy, null, 2)}</pre>
        <p style="font-size:12px;color:#6b7280;margin-top:8px">Deploy with: <code>npx @agentsid/guard</code></p>
      </div>`
    : "";

  const counts = gradeResult.counts || {};
  const summaryChips = [
    counts.CRITICAL ? `<span style="color:#dc2626;font-weight:700">${counts.CRITICAL} CRITICAL</span>` : "",
    counts.HIGH ? `<span style="color:#ea580c;font-weight:700">${counts.HIGH} HIGH</span>` : "",
    counts.MEDIUM ? `<span style="color:#ca8a04">${counts.MEDIUM} MEDIUM</span>` : "",
    counts.LOW ? `<span style="color:#2563eb">${counts.LOW} LOW</span>` : "",
  ].filter(Boolean).join(" &nbsp;·&nbsp; ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentsID Scan — ${serverInfo.name || "unknown"}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f9fafb;color:#111827;margin:0;padding:24px}
  .card{background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:24px;margin-bottom:20px}
  table{width:100%;border-collapse:collapse}
  tr:hover td{background:#fafafa}
  code{font-family:monospace;background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:12px}
  h1{margin:0 0 4px;font-size:22px}
  h2{margin:0 0 12px;font-size:16px;font-weight:700}
</style>
</head>
<body>
<div style="max-width:960px;margin:0 auto">

  <div class="card" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <h1>AgentsID Security Report</h1>
      <div style="font-size:13px;color:#6b7280">${serverInfo.name || "unknown"} v${serverInfo.version || "?"} &nbsp;·&nbsp; ${tools.length} tools &nbsp;·&nbsp; ${scannedAt}</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:64px;font-weight:900;line-height:1;color:${GRADE_COLORS[gradeResult.letter] || "#374151"}">${gradeResult.letter}</div>
      <div style="font-size:13px;color:#6b7280">${gradeResult.score}/100</div>
    </div>
  </div>

  <div class="card">
    <h2>Category Grades</h2>
    <div>${categoryBadges || "<span style='color:#6b7280;font-size:13px'>No categories</span>"}</div>
    ${riskTags ? `<div style="margin-top:12px"><span style="font-size:12px;color:#6b7280;margin-right:6px">Risk profile:</span>${riskTags}</div>` : ""}
  </div>

  <div class="card">
    <h2>Findings &nbsp;<span style="font-weight:400;font-size:14px;color:#6b7280">${gradeResult.totalFindings} total &nbsp;·&nbsp; ${summaryChips}</span></h2>
    ${findings.length > 0 ? `
    <table>
      <thead>
        <tr style="border-bottom:2px solid #e5e7eb">
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;width:90px">Severity</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280">Detail</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;width:160px">Tool</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;width:100px">Evidence</th>
        </tr>
      </thead>
      <tbody>${findingRows}</tbody>
    </table>` : `<p style="color:#16a34a;font-weight:600">No findings — excellent security posture.</p>`}
  </div>

  ${policyBlock ? `<div class="card">${policyBlock}</div>` : ""}

  <div style="text-align:center;font-size:12px;color:#9ca3af;margin-top:16px">
    Scan powered by <a href="https://agentsid.dev/scanner" style="color:#6b7280">AgentsID</a>
  </div>

</div>
</body>
</html>`;
}

export function formatJsonReport(serverInfo, tools, findings, gradeResult, riskProfile, mapPolicy) {
  return JSON.stringify({
    scanner: { name: "agentsid-scanner", version: "0.1.0" },
    scannedAt: new Date().toISOString(),
    server: serverInfo,
    toolCount: tools.length,
    grade: {
      overall: gradeResult.letter,
      score: gradeResult.score,
      categories: gradeResult.categoryGrades,
    },
    summary: gradeResult.counts,
    riskProfile,
    findings,
    ...(mapPolicy ? { mapPolicy } : {}),
  }, null, 2);
}
