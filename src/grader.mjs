/**
 * Security grader — converts scan findings into letter grades.
 *
 * Grading methodology:
 * - Start at 100 points
 * - CRITICAL findings: -25 points each
 * - HIGH findings: -15 points each
 * - MEDIUM findings: -8 points each
 * - LOW findings: -3 points each
 * - INFO findings: 0 points (informational only)
 * - Floor at 0
 *
 * Letter grades:
 * A: 90-100 (excellent security posture)
 * B: 75-89  (good, minor issues)
 * C: 60-74  (acceptable, needs improvement)
 * D: 40-59  (poor, significant risks)
 * F: 0-39   (failing, critical vulnerabilities)
 */

const SEVERITY_DEDUCTIONS = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

export function grade(findings) {
  let score = 100;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const categoryScores = {};

  for (const finding of findings) {
    const sev = finding.severity || "INFO";
    counts[sev] = (counts[sev] || 0) + 1;
    score -= SEVERITY_DEDUCTIONS[sev] || 0;

    const cat = finding.category || "other";
    if (!categoryScores[cat]) categoryScores[cat] = 100;
    categoryScores[cat] -= SEVERITY_DEDUCTIONS[sev] || 0;
  }

  score = Math.max(0, score);
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
