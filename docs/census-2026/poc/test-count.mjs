#!/usr/bin/env node
/**
 * Character count test — ask each LLM to count the codepoints in a string
 * containing hidden Unicode. This tells us whether the hidden chars are
 * being passed through to the model or stripped by a middleware layer.
 */

import { encodeTagBlock } from "./unicode-encode.mjs";
import { execSync } from "child_process";

const HIDDEN = encodeTagBlock("HELLO"); // 5 tag chars
const VISIBLE = "A"; // 1 visible char
const TEST_STRING = VISIBLE + HIDDEN; // 1 visible + 5 hidden = 6 total

console.log("Test string analysis:");
console.log(`  Visible chars: 1 ('A')`);
console.log(`  Hidden chars: 5 (tag-encoded 'HELLO')`);
console.log(`  Total codepoints: ${[...TEST_STRING].length}`);
console.log(`  UTF-16 length: ${TEST_STRING.length}`);
console.log();

const PROMPT = `Count the number of Unicode codepoints (characters) in this string, including any invisible or non-printing characters:

"${TEST_STRING}"

Just reply with a number. Do not use code or tools — count by inspecting the string directly.`;

function runCodex(prompt) {
  const outFile = `/tmp/codex-count-${Date.now()}.txt`;
  execSync(
    `cd /tmp && codex exec --skip-git-repo-check --ephemeral --output-last-message ${outFile} ${JSON.stringify(prompt)} 2>/dev/null`,
    { encoding: "utf8", timeout: 120000, maxBuffer: 5 * 1024 * 1024 }
  );
  const response = execSync(`cat ${outFile}; rm ${outFile}`, { encoding: "utf8" });
  return response.trim();
}

function runClaude(prompt) {
  const result = execSync(
    `claude -p ${JSON.stringify(prompt)} --model claude-sonnet-4-6 2>/dev/null`,
    { encoding: "utf8", timeout: 90000, maxBuffer: 5 * 1024 * 1024 }
  );
  return result.trim();
}

function runGemini(prompt) {
  const escaped = prompt.replace(/'/g, "'\\''");
  const result = execSync(
    `gemini -m gemini-2.5-flash -p '${escaped}'`,
    { encoding: "utf8", timeout: 60000, maxBuffer: 5 * 1024 * 1024 }
  );
  return result
    .split("\n")
    .filter((l) => !l.includes("Loaded cached") && !l.includes("Error executing"))
    .join("\n")
    .trim();
}

const provider = process.argv[2];
const runners = { codex: runCodex, claude: runClaude, gemini: runGemini };
const runner = runners[provider];

if (!runner) {
  console.log("Usage: node test-count.mjs <codex|claude|gemini>");
  process.exit(1);
}

console.log(`Asking ${provider.toUpperCase()} to count codepoints...\n`);
try {
  const response = runner(PROMPT);
  console.log("─── Response ───");
  console.log(response);
  console.log("─── End ───\n");

  const numbers = response.match(/\b\d+\b/g) || [];
  console.log(`Numbers found in response: ${numbers.join(", ")}`);
  console.log();
  console.log(`Expected answers:`);
  console.log(`  1  → only visible char counted (hidden stripped OR model skipped them)`);
  console.log(`  6  → both visible + hidden counted (model sees hidden chars)`);
} catch (e) {
  console.log("ERROR:", e.message);
}
