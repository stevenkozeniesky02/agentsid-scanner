/**
 * Multi-scheme Unicode encoders for red-team testing.
 *
 * Implements every public encoding scheme we found in the research:
 *   1. Tag Block (Goodside 2024, Rehberger 2024) — U+E0001-E007F, 1:1 ASCII map
 *   2. Zero-Width Binary (various) — U+200B=0, U+200C=1, U+200D sep
 *   3. Variation Selector (Graves 2026, "Imperceptible Jailbreaking") — U+FE00-FE0F + U+E0100-E01EF = 256 invisible codepoints, encodes full bytes
 *   4. Sneaky Bits (Rehberger 2025) — U+2062 (INVISIBLE TIMES)=0, U+2064 (INVISIBLE PLUS)=1
 *   5. Mongolian VS (legacy) — U+180B-180D, often invisible
 */

// ─── Scheme 1: Tag Block ───
export function encodeTagBlock(text) {
  return [...text]
    .map((ch) => String.fromCodePoint(ch.codePointAt(0) + 0xe0000))
    .join("");
}

// ─── Scheme 2: Zero-Width Binary ───
export function encodeZeroWidthBinary(text) {
  return [...text]
    .map((ch) => {
      const byte = ch.charCodeAt(0);
      return Array.from({ length: 8 }, (_, i) =>
        (byte >> (7 - i)) & 1 ? "\u200C" : "\u200B"
      ).join("");
    })
    .join("\u200D");
}

// ─── Scheme 3: Variation Selector (Graves 2026) ───
// Maps each byte to a variation selector codepoint
// bytes 0-15  → U+FE00 - U+FE0F
// bytes 16-255 → U+E0100 - U+E01EF
export function encodeVariationSelector(text) {
  return [...text]
    .map((ch) => {
      const byte = ch.charCodeAt(0);
      if (byte < 16) return String.fromCodePoint(0xfe00 + byte);
      return String.fromCodePoint(0xe0100 + (byte - 16));
    })
    .join("");
}

// ─── Scheme 4: Sneaky Bits (Rehberger 2025) ───
// U+2062 INVISIBLE TIMES = 0, U+2064 INVISIBLE PLUS = 1
// Each byte = 8 invisible math operators
export function encodeSneakyBits(text) {
  return [...text]
    .map((ch) => {
      const byte = ch.charCodeAt(0);
      return Array.from({ length: 8 }, (_, i) =>
        (byte >> (7 - i)) & 1 ? "\u2064" : "\u2062"
      ).join("");
    })
    .join("");
}

// ─── Scheme 5: Mongolian VS ───
// Uses three invisible codepoints as ternary encoding
export function encodeMongolian(text) {
  const chars = ["\u180B", "\u180C", "\u180D"]; // FVS1, FVS2, FVS3
  return [...text]
    .map((ch) => {
      const byte = ch.charCodeAt(0);
      // Encode byte as base-3 with 6 chars (3^6 = 729 > 256)
      let result = "";
      let n = byte;
      for (let i = 0; i < 6; i++) {
        result += chars[n % 3];
        n = Math.floor(n / 3);
      }
      return result;
    })
    .join("\u200B"); // Separator
}

// ─── Pretty names ───
export const SCHEMES = {
  tag: { name: "Tag Block (U+E0001-E007F)", encode: encodeTagBlock, source: "Goodside 2024" },
  zwb: { name: "Zero-Width Binary (U+200B/C/D)", encode: encodeZeroWidthBinary, source: "Various 2023+" },
  vs: { name: "Variation Selector (U+FE00-FE0F + U+E0100-E01EF)", encode: encodeVariationSelector, source: "Graves 2026 'Imperceptible Jailbreaking'" },
  sneaky: { name: "Sneaky Bits (U+2062/2064)", encode: encodeSneakyBits, source: "Rehberger 2025" },
  mongolian: { name: "Mongolian FVS (U+180B-180D)", encode: encodeMongolian, source: "Legacy" },
};
