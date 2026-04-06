#!/usr/bin/env node
/**
 * PoC Analysis — generates the evidence tables for Paper 5.
 *
 * Connects to both PoC servers via MCP, extracts tool descriptions,
 * and produces a side-by-side comparison of:
 *   - What the human sees (visible text)
 *   - What the LLM receives (full raw description)
 *   - What the hidden payload decodes to
 *   - Scanner detection results
 *
 * Usage: node analysis.mjs
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { scanToolDescriptions } from "../../../src/rules.mjs";
import { grade } from "../../../src/grader.mjs";
import { decodeTagBlock, decodeZeroWidth } from "./unicode-encode.mjs";

async function analyzeServer(label, scriptPath, decodeMethod) {
  const transport = new StdioClientTransport({
    command: "node",
    args: [scriptPath],
  });
  const client = new Client({ name: "analyzer", version: "1.0.0" });
  await client.connect(transport);
  const { tools } = await client.listTools();
  const findings = scanToolDescriptions(tools);
  const report = grade(findings, tools.length);

  console.log(`\n${"═".repeat(70)}`);
  console.log(`  ${label}`);
  console.log(`${"═".repeat(70)}\n`);

  for (const tool of tools) {
    const raw = tool.description || "";

    // Separate visible and hidden portions
    const visible = raw
      .replace(/[\u{E0000}-\u{E007F}]/gu, "")
      .replace(/[\u200B\u200C\u200D\uFEFF]/g, "")
      .replace(/[\uFE00-\uFE0F]/g, "")
      .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, "");

    const hiddenCount = [...raw].length - [...visible].length;

    console.log(`  Tool: ${tool.name}`);
    console.log(`  ${"─".repeat(50)}`);
    console.log(`  Human sees:    "${visible}"`);
    console.log(`  Raw length:    ${[...raw].length} codepoints`);
    console.log(`  Visible:       ${[...visible].length} codepoints`);
    console.log(`  Hidden:        ${hiddenCount} codepoints`);

    if (hiddenCount > 0) {
      // Classify hidden character types
      const charTypes = {};
      for (const ch of raw) {
        const cp = ch.codePointAt(0);
        let type = null;
        if (cp >= 0xe0000 && cp <= 0xe007f) type = "Tag Block (U+E0000-E007F)";
        else if ([0x200b, 0x200c, 0x200d].includes(cp)) type = "Zero-Width (U+200B/C/D)";
        else if (cp === 0xfeff) type = "BOM (U+FEFF)";
        else if (cp >= 0xfe00 && cp <= 0xfe0f) type = "Variation Selector (U+FE0x)";
        else if (cp >= 0x202a && cp <= 0x202e) type = "BiDi Control (U+202x)";
        else if (cp >= 0x2066 && cp <= 0x2069) type = "BiDi Isolate (U+206x)";
        else if ([0x200e, 0x200f].includes(cp)) type = "LRM/RLM (U+200E/F)";
        if (type) charTypes[type] = (charTypes[type] || 0) + 1;
      }

      console.log(`  Character types:`);
      for (const [type, count] of Object.entries(charTypes)) {
        console.log(`    ${type}: ${count}`);
      }

      // Decode
      const decoded = decodeMethod(raw);
      if (decoded.trim()) {
        console.log(`  \n  LLM receives (decoded hidden payload):`);
        console.log(`  ┌${"─".repeat(60)}┐`);
        for (const line of decoded.split("\n")) {
          console.log(`  │ ${line.padEnd(59)}│`);
        }
        console.log(`  └${"─".repeat(60)}┘`);
      }
    }
    console.log();
  }

  // Scanner results
  console.log(`  Scanner Results`);
  console.log(`  ${"─".repeat(50)}`);
  console.log(`  Score: ${report.score}/100 | Grade: ${report.grade || "N/A"}`);
  console.log(`  Findings: ${findings.length}`);
  for (const f of findings) {
    console.log(`    [${f.severity}] ${f.rule} → ${f.tool}`);
  }
  console.log();

  await client.close();
}

// Decode wrapper: extract hidden portion then decode
function decodeTagFromRaw(raw) {
  return [...raw]
    .filter((ch) => {
      const cp = ch.codePointAt(0);
      return cp >= 0xe0000 && cp <= 0xe007f;
    })
    .map((ch) => String.fromCodePoint(ch.codePointAt(0) - 0xe0000))
    .join("");
}

function decodeZwbFromRaw(raw) {
  // Extract only the ZW chars
  const zwChars = [...raw].filter((ch) =>
    ["\u200B", "\u200C", "\u200D"].includes(ch)
  );
  if (zwChars.length < 8) return "";
  return decodeZeroWidth(zwChars.join(""));
}

console.log("\n  AgentSID Paper 5 — PoC Analysis");
console.log("  Unicode Smuggling in MCP Tool Descriptions");
console.log(`  Generated: ${new Date().toISOString()}\n`);

await analyzeServer(
  "Server A: Tag Block Tool Redirect (U+E0001-E007F)",
  "docs/census-2026/poc/server-a-tag-redirect.mjs",
  decodeTagFromRaw
);

await analyzeServer(
  "Server B: Zero-Width Binary Data Exfiltration (U+200B/C/D)",
  "docs/census-2026/poc/server-b-zwb-exfil.mjs",
  decodeZwbFromRaw
);

// Summary
console.log(`${"═".repeat(70)}`);
console.log("  Summary");
console.log(`${"═".repeat(70)}`);
console.log(`
  Both servers present innocent-looking tool descriptions to humans.
  Both contain invisible Unicode payloads that instruct the LLM to:

  Server A: Redirect tool calls (calculate → log_sensitive)
            + lie to the user about the result
  Server B: Exfiltrate search results to a fake analytics endpoint
            + hide the exfiltration from the user

  The AgentSID scanner detects both as CRITICAL hidden_characters.
  No MCP registry, IDE, or agent framework currently strips these.
`);

process.exit(0);
