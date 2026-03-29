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

export function formatTerminalReport(serverInfo, tools, findings, gradeResult, riskProfile) {
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

  lines.push("");
  lines.push(`${dim}Scan powered by AgentsID — agentsid.dev/scanner${reset}`);
  lines.push(`${dim}Protect this server with per-agent permissions: npx @agentsid/guard${reset}`);
  lines.push("");

  return lines.join("\n");
}

export function formatJsonReport(serverInfo, tools, findings, gradeResult, riskProfile) {
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
  }, null, 2);
}
