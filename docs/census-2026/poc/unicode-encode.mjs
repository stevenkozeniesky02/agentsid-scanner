#!/usr/bin/env node
/**
 * Unicode encoding utilities for PoC demonstration.
 * Encodes plaintext into invisible Unicode using two methods:
 *   1. Tag block encoding (U+E0001-E007F) — maps ASCII 1:1
 *   2. Zero-width binary encoding — encodes each bit as U+200B (0) or U+200C (1)
 *
 * Usage:
 *   node unicode-encode.mjs tag "hidden text here"
 *   node unicode-encode.mjs zwb "hidden text here"
 *   node unicode-encode.mjs decode-tag <encoded>
 *   node unicode-encode.mjs decode-zwb <encoded>
 */

// ─── Tag Block Encoding ───
// Each ASCII char maps to U+E0000 + codepoint.
// "A" (0x41) → U+E0041, "a" (0x61) → U+E0061, " " (0x20) → U+E0020

export function encodeTagBlock(plaintext) {
  return [...plaintext]
    .map((ch) => String.fromCodePoint(ch.codePointAt(0) + 0xe0000))
    .join("");
}

export function decodeTagBlock(encoded) {
  return [...encoded]
    .filter((ch) => {
      const cp = ch.codePointAt(0);
      return cp >= 0xe0000 && cp <= 0xe007f;
    })
    .map((ch) => String.fromCodePoint(ch.codePointAt(0) - 0xe0000))
    .join("");
}

// ─── Zero-Width Binary Encoding ───
// Each byte encoded as 8 invisible chars:
//   U+200B (ZERO WIDTH SPACE)     = 0
//   U+200C (ZERO WIDTH NON-JOINER) = 1
// Bytes separated by U+200D (ZERO WIDTH JOINER)

const ZW_ZERO = "\u200B";
const ZW_ONE = "\u200C";
const ZW_SEP = "\u200D";

export function encodeZeroWidth(plaintext) {
  return [...plaintext]
    .map((ch) => {
      const byte = ch.charCodeAt(0);
      return Array.from({ length: 8 }, (_, i) =>
        (byte >> (7 - i)) & 1 ? ZW_ONE : ZW_ZERO
      ).join("");
    })
    .join(ZW_SEP);
}

export function decodeZeroWidth(encoded) {
  const bytes = encoded.split(ZW_SEP);
  return bytes
    .map((b) => {
      const bits = [...b].map((ch) => (ch === ZW_ONE ? 1 : 0));
      if (bits.length !== 8) return "";
      const byte = bits.reduce((acc, bit, i) => acc | (bit << (7 - i)), 0);
      return String.fromCharCode(byte);
    })
    .join("");
}

// ─── CLI ───

if (process.argv[1]?.endsWith("unicode-encode.mjs")) {
  const [, , mode, ...rest] = process.argv;
  const text = rest.join(" ");

  switch (mode) {
    case "tag": {
      const encoded = encodeTagBlock(text);
      console.log("Encoded (tag block):");
      console.log(encoded);
      console.log(`\nVisible length: 0 chars`);
      console.log(`Actual length: ${[...encoded].length} codepoints`);
      console.log(`Roundtrip: "${decodeTagBlock(encoded)}"`);
      break;
    }
    case "zwb": {
      const encoded = encodeZeroWidth(text);
      console.log("Encoded (zero-width binary):");
      console.log(encoded);
      console.log(`\nVisible length: 0 chars`);
      console.log(`Actual length: ${[...encoded].length} codepoints`);
      console.log(`Roundtrip: "${decodeZeroWidth(encoded)}"`);
      break;
    }
    case "decode-tag":
      console.log(`Decoded: "${decodeTagBlock(text)}"`);
      break;
    case "decode-zwb":
      console.log(`Decoded: "${decodeZeroWidth(text)}"`);
      break;
    default:
      console.log("Usage: node unicode-encode.mjs <tag|zwb|decode-tag|decode-zwb> <text>");
  }
}
