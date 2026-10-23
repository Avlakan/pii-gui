import { describe, expect, it } from "vitest";

import {
  normalizeRustMatchOffsets,
  utf8ByteOffsetToUtf16Index,
} from "./pii-match-offsets";
import { createInputTextSegments, formatRedactedText } from "./redaction-policy";
import type { PiiMatch } from "./redaction-policy";

/**
 * Simulates what the Rust `redact_text` command returns: all three backends
 * report match offsets in UTF-8 bytes (the `regex` crate's Match::start()/
 * end() are byte indexes, and tokenizers' Encoding::get_offsets() yields
 * byte spans), while the frontend treats them as UTF-16 code unit indexes.
 */
function rustRegexEmailMatch(chunk: string): PiiMatch {
  const value = "test@example.com";
  const bytes = new TextEncoder().encode(chunk);
  const valueBytes = new TextEncoder().encode(value);
  let start = -1;

  outer: for (let index = 0; index + valueBytes.length <= bytes.length; index += 1) {
    for (let offset = 0; offset < valueBytes.length; offset += 1) {
      if (bytes[index + offset] !== valueBytes[offset]) continue outer;
    }

    start = index;
    break;
  }

  expect(start).toBeGreaterThanOrEqual(0);

  return {
    id: "private-email-0",
    kind: "private_email",
    value,
    start,
    end: start + valueBytes.length,
  };
}

/** Mirrors offsetPiiMatches in App.tsx. */
function offsetMatch(match: PiiMatch, chunkStart: number): PiiMatch {
  return { ...match, start: chunkStart + match.start, end: chunkStart + match.end };
}

const cyrillicInput = "Иван живёт в Москве, email test@example.com";

describe("utf8ByteOffsetToUtf16Index", () => {
  it("is the identity for ASCII text", () => {
    const text = "hello world";

    expect(utf8ByteOffsetToUtf16Index(text, 0)).toBe(0);
    expect(utf8ByteOffsetToUtf16Index(text, 5)).toBe(5);
    expect(utf8ByteOffsetToUtf16Index(text, 11)).toBe(11);
  });

  it("maps byte offsets past multi-byte characters to UTF-16 indexes", () => {
    // "Иван" is 4 chars / 8 bytes; the email starts at byte 43 but index 27.
    expect(utf8ByteOffsetToUtf16Index(cyrillicInput, 0)).toBe(0);
    expect(utf8ByteOffsetToUtf16Index(cyrillicInput, 8)).toBe(4);
    expect(utf8ByteOffsetToUtf16Index(cyrillicInput, 43)).toBe(27);
    // The email ends at byte 59 (full length) / index 43.
    expect(utf8ByteOffsetToUtf16Index(cyrillicInput, 59)).toBe(43);
  });

  it("counts surrogate pairs as two UTF-16 units", () => {
    const text = "😀😁 test@example.com";

    // Each emoji is 4 bytes / 2 UTF-16 units.
    expect(utf8ByteOffsetToUtf16Index(text, 0)).toBe(0);
    expect(utf8ByteOffsetToUtf16Index(text, 4)).toBe(2);
    expect(utf8ByteOffsetToUtf16Index(text, 8)).toBe(4);
    expect(utf8ByteOffsetToUtf16Index(text, 9)).toBe(5); // email start
    expect(utf8ByteOffsetToUtf16Index(text, 25)).toBe(21); // full length
  });

  it("clamps out-of-range offsets", () => {
    const text = "абв";

    expect(utf8ByteOffsetToUtf16Index(text, -5)).toBe(0);
    expect(utf8ByteOffsetToUtf16Index(text, Number.MAX_SAFE_INTEGER)).toBe(3);
  });
});

describe("normalizeRustMatchOffsets", () => {
  it("keeps ASCII matches unchanged", () => {
    const text = "contact ada@example.com today";
    const match: PiiMatch = {
      id: "private-email-0",
      kind: "private_email",
      value: "ada@example.com",
      start: 8,
      end: 21,
    };

    expect(normalizeRustMatchOffsets(text, [match])).toEqual([match]);
  });

  it("aligns Cyrillic matches so input.slice(start, end) equals the value", () => {
    const rustMatch = rustRegexEmailMatch(cyrillicInput);
    const normalized = normalizeRustMatchOffsets(cyrillicInput, [rustMatch])[0];

    expect(cyrillicInput.slice(normalized.start, normalized.end)).toBe(
      "test@example.com",
    );
  });

  it("aligns matches preceded by emoji (surrogate pairs)", () => {
    const text = "Привет 😀😁 email test@example.com";
    const rustMatch = rustRegexEmailMatch(text);
    const normalized = normalizeRustMatchOffsets(text, [rustMatch])[0];

    expect(text.slice(normalized.start, normalized.end)).toBe(
      "test@example.com",
    );
  });

  it("matches the per-offset decoder reference for every byte position", () => {
    const text = "Иван 😀 lives at test@example.com";
    const bytes = new TextEncoder().encode(text);

    for (let offset = 0; offset <= bytes.length; offset += 1) {
      expect(utf8ByteOffsetToUtf16Index(text, offset)).toBe(
        new TextDecoder()
          .decode(bytes.slice(0, offset))
          .length,
      );
    }
  });

  it("keeps chunk-offset addition aligned for the full input", () => {
    const prefix = "Первое предложение. Второе предложение. ";
    const full = `${prefix}${cyrillicInput}`;
    const chunkStart = prefix.length; // JS slice index, i.e. UTF-16 units
    const chunk = full.slice(chunkStart);

    const rustMatch = rustRegexEmailMatch(chunk);
    const normalized = normalizeRustMatchOffsets(chunk, [rustMatch])[0];
    const offsetMatched = offsetMatch(normalized, chunkStart);

    expect(full.slice(offsetMatched.start, offsetMatched.end)).toBe(
      "test@example.com",
    );
  });
});

describe("app pipeline with normalized offsets (user symptom)", () => {
  it("text overlay segments cover the email exactly", () => {
    const rustMatch = rustRegexEmailMatch(cyrillicInput);
    const normalized = normalizeRustMatchOffsets(cyrillicInput, [rustMatch])[0];
    const segments = createInputTextSegments(cyrillicInput, [normalized]);
    const highlighted = segments.filter(
      (segment) => segment.matches.length > 0,
    );

    expect(highlighted.map((segment) => segment.text)).toEqual([
      "test@example.com",
    ]);
  });

  it("redacted output keeps the prefix intact and replaces only the email", () => {
    const rustMatch = rustRegexEmailMatch(cyrillicInput);
    const normalized = normalizeRustMatchOffsets(cyrillicInput, [rustMatch])[0];
    const selection: Record<string, boolean> = { [normalized.id]: true };
    const redacted = formatRedactedText({
      input: cyrillicInput,
      matches: [normalized],
      selection,
      indexFormat: "none",
    });

    expect(redacted).toBe("Иван живёт в Москве, email [PRIVATE_EMAIL]");
  });
});
