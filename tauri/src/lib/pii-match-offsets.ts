import type { PiiMatch } from "./redaction-policy";

/**
 * Rust reports match offsets in UTF-8 bytes (the `regex` crate's
 * Match::start()/end() are byte indexes, and tokenizers'
 * Encoding::get_offsets() yields byte spans), while the frontend slices JS
 * strings by UTF-16 code units. This module converts Rust offsets into
 * UTF-16 indexes so chunk offsets can be added safely downstream.
 */

/**
 * Converts a UTF-8 byte offset in `text` to the UTF-16 index of the same
 * position, matching `new TextDecoder().decode(bytes.slice(0, offset)).length`.
 * Offsets are clamped; an offset inside a multi-byte sequence maps past the
 * replacement character the decoder emits for it.
 */
export function utf8ByteOffsetToUtf16Index(
  text: string,
  byteOffset: number,
): number {
  const bytes = new TextEncoder().encode(text);
  const safeOffset = Math.max(0, Math.min(byteOffset, bytes.length));

  return new TextDecoder()
    .decode(bytes.slice(0, safeOffset))
    .length;
}

/**
 * Re-expresses Rust match offsets (UTF-8 bytes) as UTF-16 indexes into the
 * same string. The input is encoded once and every offset resolves against a
 * precomputed byte/UTF-16 table, so converting many matches costs one encode
 * plus O(total bytes) instead of one full decode per match.
 */
export function normalizeRustMatchOffsets(
  text: string,
  matches: PiiMatch[],
): PiiMatch[] {
  const encoder = new TextEncoder();
  // utf16IndexAtByte[k] is the UTF-16 index at byte position k of `text`.
  const utf16IndexAtByte: number[] = [0];

  for (const character of text) {
    const byteLength = encoder.encode(character).length;
    const unitLength = character.length; // UTF-16 units this char occupies
    const before = utf16IndexAtByte[utf16IndexAtByte.length - 1];

    // A partial multi-byte sequence decodes to one replacement character.
    for (let step = 1; step < byteLength; step += 1) {
      utf16IndexAtByte.push(before + 1);
    }
    utf16IndexAtByte.push(before + unitLength);
  }

  return matches.map((match) => ({
    ...match,
    start: resolveOffset(match.start),
    end: resolveOffset(match.end),
  }));

  function resolveOffset(byteOffset: number): number {
    const safeOffset = Math.max(
      0,
      Math.min(Math.trunc(byteOffset), utf16IndexAtByte.length - 1),
    );

    return utf16IndexAtByte[safeOffset];
  }
}
