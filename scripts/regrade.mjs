#!/usr/bin/env node
/**
 * Regrade all existing reports using the updated grading algorithm.
 * Reads each report JSON, runs grade(findings, toolCount), and writes
 * the updated score/grade back. Does NOT re-scan servers.
 *
 * Usage:
 *   node scripts/regrade.mjs
 *   node scripts/regrade.mjs --dry-run    # preview without writing
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { grade } from "../src/grader.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, "../reports");
const DRY_RUN = process.argv.includes("--dry-run");

const files = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".json"));

let total = 0;
let changed = 0;
let errors = 0;
const gradeShifts = { upgraded: 0, downgraded: 0, same: 0 };
const scoreDiffs = [];

for (const file of files) {
  const filePath = path.join(REPORTS_DIR, file);
  try {
    const report = JSON.parse(fs.readFileSync(filePath, "utf8"));

    if (!report.findings || !Array.isArray(report.findings)) {
      continue;
    }

    const oldScore = report.grade?.score ?? 0;
    const oldLetter = report.grade?.overall ?? "F";
    const toolCount = report.toolCount ?? 1;

    const result = grade(report.findings, toolCount);

    const diff = result.score - oldScore;
    scoreDiffs.push(diff);

    if (result.score > oldScore) gradeShifts.upgraded++;
    else if (result.score < oldScore) gradeShifts.downgraded++;
    else gradeShifts.same++;

    if (result.score !== oldScore || result.letter !== oldLetter) {
      changed++;

      if (!DRY_RUN) {
        const updated = {
          ...report,
          grade: {
            overall: result.letter,
            score: result.score,
            categories: result.categoryGrades,
          },
          summary: {
            CRITICAL: result.counts.CRITICAL,
            HIGH: result.counts.HIGH,
            MEDIUM: result.counts.MEDIUM,
            LOW: result.counts.LOW,
            INFO: result.counts.INFO,
          },
        };
        fs.writeFileSync(filePath, JSON.stringify(updated, null, 2));
      }
    }

    total++;
  } catch (err) {
    errors++;
  }
}

// Stats
const avgDiff = scoreDiffs.length > 0
  ? (scoreDiffs.reduce((a, b) => a + b, 0) / scoreDiffs.length).toFixed(1)
  : 0;

const letterDist = {};
for (const file of files) {
  try {
    const report = JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, file), "utf8"));
    const letter = report.grade?.overall ?? "?";
    letterDist[letter] = (letterDist[letter] || 0) + 1;
  } catch {}
}

console.log(`\n${DRY_RUN ? "DRY RUN — " : ""}Regrade complete`);
console.log(`  Total reports:  ${total}`);
console.log(`  Changed:        ${changed}`);
console.log(`  Errors:         ${errors}`);
console.log(`  Upgraded:       ${gradeShifts.upgraded}`);
console.log(`  Downgraded:     ${gradeShifts.downgraded}`);
console.log(`  Unchanged:      ${gradeShifts.same}`);
console.log(`  Avg score diff: +${avgDiff}`);
console.log(`\n  Grade distribution:`);
for (const letter of ["A", "B", "C", "D", "F"]) {
  console.log(`    ${letter}: ${letterDist[letter] || 0}`);
}
console.log();
