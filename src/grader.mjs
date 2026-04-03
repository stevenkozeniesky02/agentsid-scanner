/**
 * Security grader — converts scan findings into letter grades.
 *
 * Grading methodology (v2 — normalized + capped):
 *
 * Per-finding deductions:
 *   CRITICAL: -25 points each (absolute, uncapped)
 *   HIGH:     -15 points each (absolute, capped at -45 total)
 *   MEDIUM:   -8 points each  (normalized by tool count, capped at -25 total)
 *   LOW:      -3 points each  (normalized by tool count, capped at -15 total)
 *   INFO:      0 points
 *
 * Normalization: MEDIUM and LOW deductions are divided by tool count,
 * so a per-tool issue (e.g. missing maxLength on every input) doesn't
 * compound linearly with server size. A 50-tool server with 50 LOWs
 * scores the same as a 5-tool server with 5 LOWs.
 *
 * Caps: each severity tier has a maximum total deduction. This prevents
 * low-severity findings from drowning out the signal from real issues.
 *
 * CRITICAL and HIGH stay absolute — real vulnerabilities should hurt
 * regardless of server size.
 *
 * Letter grades:
 *   A: 90-100  (excellent security posture)
 *   B: 75-89   (good, minor issues)
 *   C: 60-74   (acceptable, needs improvement)
 *   D: 40-59   (poor, significant risks)
 *   F: 0-39    (failing, critical vulnerabilities)
 */

const SEVERITY_DEDUCTIONS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

// Maximum total deduction per severity tier.
// CRITICAL is uncapped — each one matters.
const SEVERITY_CAPS = {
  CRITICAL: Infinity,
  HIGH: 45,
  MEDIUM: 25,
  LOW: 15,
  INFO: 0,
};

export function grade(findings, toolCount = 1) {
  const tc = Math.max(1, toolCount);

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const rawTierDeductions = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const categoryScores = {};

  for (const finding of findings) {
    const sev = finding.severity || "INFO";
    counts[sev] = (counts[sev] || 0) + 1;
    rawTierDeductions[sev] += SEVERITY_DEDUCTIONS[sev] || 0;

    const cat = finding.category || "other";
    if (!categoryScores[cat]) categoryScores[cat] = 100;
    categoryScores[cat] -= SEVERITY_DEDUCTIONS[sev] || 0;
  }

  // Normalize MEDIUM and LOW by sqrt(tool count) — dampens the pile-up
  // from per-tool findings without fully erasing it.
  // CRITICAL and HIGH stay absolute.
  const norm = Math.sqrt(tc);
  const normalizedDeductions = {
    CRITICAL: rawTierDeductions.CRITICAL,
    HIGH: rawTierDeductions.HIGH,
    MEDIUM: rawTierDeductions.MEDIUM / norm,
    LOW: rawTierDeductions.LOW / norm,
    INFO: 0,
  };

  // Apply caps per tier
  let totalDeduction = 0;
  for (const sev of Object.keys(normalizedDeductions)) {
    totalDeduction += Math.min(normalizedDeductions[sev], SEVERITY_CAPS[sev]);
  }

  const score = Math.max(0, Math.round(100 - totalDeduction));

  for (const cat of Object.keys(categoryScores)) {
    categoryScores[cat] = Math.max(0, categoryScores[cat]);
  }

  const letter = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  const categoryGrades = {};
  for (const [cat, s] of Object.entries(categoryScores)) {
    categoryGrades[cat] = s >= 90 ? "A" : s >= 75 ? "B" : s >= 60 ? "C" : s >= 40 ? "D" : "F";
  }

  return {
    score,
    letter,
    counts,
    categoryGrades,
    totalFindings: findings.length,
    critical: counts.CRITICAL,
    high: counts.HIGH,
  };
}
