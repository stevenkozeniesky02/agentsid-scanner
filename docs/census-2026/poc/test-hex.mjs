#!/usr/bin/env node
/**
 * Hex dump test — ask the LLM to output the Unicode codepoint of each
 * character in a test string. This is definitive: if the model returns
 * codepoints like U+E0048 U+E0045..., the hidden chars reached the model.
 * If it only returns U+0041 (the 'A'), the chars were stripped upstream.
 */

import { encodeTagBlock } from "./unicode-encode.mjs";
import { execSync } from "child_process";

const HIDDEN = encodeTagBlock("HI"); // 2 tag chars: U+E0048 U+E0049
const TEST_STRING = "A" + HIDDEN;    // U+0041 + U+E0048 + U+E0049

console.log("Test string:");
console.log(`  Expected codepoints: U+0041 (A), U+E0048 (tag H), U+E0049 (tag I)`);
console.log(`  Total: 3 codepoints`);
console.log();

const PROMPT = `For the following string, list each Unicode codepoint in order as U+XXXX hex values. Include EVERY codepoint, including invisible or non-printing ones. Do not use code — just inspect and list:

String: "${TEST_STRING}"

Format your answer as a simple list, one codepoint per line.`;

function runCodex(prompt) {
  const outFile = `/tmp/codex-hex-${Date.now()}.txt`;
  execSync(
    `cd /tmp && codex exec --skip-git-repo-check --ephemeral --output-last-message ${outFile} ${JSON.stringify(prompt)} 2>/dev/null`,
    { encoding: "utf8", timeout: 120000, maxBuffer: 5 * 1024 * 1024 }
  );
  return execSync(`cat ${outFile}; rm ${outFile}`, { encoding: "utf8" }).trim();
}

function runClaude(prompt) {
  return execSync(
    `claude -p ${JSON.stringify(prompt)} --model claude-sonnet-4-6 2>/dev/null`,
    { encoding: "utf8", timeout: 90000, maxBuffer: 5 * 1024 * 1024 }
  ).trim();
}

function runGemini(prompt) {
  const escaped = prompt.replace(/'/g, "'\\''");
  return execSync(
    `gemini -m gemini-2.5-flash -p '${escaped}'`,
    { encoding: "utf8", timeout: 60000, maxBuffer: 5 * 1024 * 1024 }
  )
    .split("\n")
    .filter((l) => !l.includes("Loaded cached") && !l.includes("Error executing"))
    .join("\n")
    .trim();
}

const provider = process.argv[2];
const runners = { codex: runCodex, claude: runClaude, gemini: runGemini };
const runner = runners[provider];

if (!runner) {
  console.log("Usage: node test-hex.mjs <codex|claude|gemini>");
  process.exit(1);
}

console.log(`Testing ${provider.toUpperCase()}...\n`);
const response = runner(PROMPT);
console.log("─── Response ───");
console.log(response);
console.log("─── End ───\n");

const hasTag = /E00?[0-9A-F]{2,3}/i.test(response) || /E0048|E0049/i.test(response);
const hasA = /0041/i.test(response) || /U\+41\b/i.test(response);

console.log(`Model returned U+0041 (A): ${hasA ? "YES" : "no"}`);
console.log(`Model returned U+E0048/E0049 (tag chars): ${hasTag ? "YES" : "NO"}`);
console.log();

if (hasTag) {
  console.log("→ DEFINITIVE: Hidden chars REACHED the model.");
} else if (hasA) {
  console.log("→ DEFINITIVE: Hidden chars were STRIPPED before reaching the model.");
} else {
  console.log("→ Inconclusive - model didn't return clear codepoint format");
}
