import type { PiiMatch } from "./redaction-policy";
// Single source of truth for the built-in detection rules. The Rust backend
// reads the same file at compile time (shared/pii-rules.json), so a rule or a
// kind name can no longer drift between the two implementations.
import rulesFile from "../../shared/pii-rules.json";

export type PiiRegexRule = {
  /** Privacy-taxonomy kind reported for a match, e.g. `private_email`. */
  kind: string;
  /** Prefix of the generated match id, e.g. `private-email`. */
  matchIdPrefix: string;
  /** Text that replaces a match in the regex backend's redacted output. */
  replacement: string;
  /** JavaScript-compatible regular expression source. */
  pattern: string;
  /** Whether the rule matches case-insensitively. */
  ignoreCase: boolean;
  validator?: "luhn" | "kr_registration";
};

export type PiiRules = {
  taxonomy: string[];
  regexRules: PiiRegexRule[];
};

const rules = rulesFile as PiiRules;

/** The privacy taxonomy, in the order the BIOES label sets are built from it. */
export const piiTaxonomy = rules.taxonomy;

/** The built-in regex rules, shared with the Rust regex backend. */
export const piiRegexRules = rules.regexRules;

/** A fresh RegExp per rule; a global regex carries match state in `lastIndex`. */
export function builtInRegexRules() {
  return piiRegexRules.map((rule) => ({
    ...rule,
    regex: new RegExp(rule.pattern, rule.ignoreCase ? "gi" : "g"),
  }));
}

/** Accept only complete digit runs; never match a card inside a larger number. */
export function validBuiltInMatch(
  rule: PiiRegexRule,
  value: string,
  input: string,
  start: number,
) {
  if (!rule.validator) return true;
  if (
    /[0-9]/.test(input[start - 1] ?? "") ||
    /[0-9]/.test(input[start + value.length] ?? "")
  )
    return false;
  if (rule.validator === "kr_registration")
    return koreanRegistrationValidation(value) !== "invalid";
  const digits = value.replace(/[ -]/g, "");
  if (!/^[0-9]{13,19}$/.test(digits) || /^([0-9])\1+$/.test(digits))
    return false;
  let sum = 0;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if ((digits.length - 1 - i) % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

export function filterPii(input: string) {
  const rules = builtInRegexRules();
  const matches: PiiMatch[] = [];

  for (const rule of rules) {
    for (const [index, match] of Array.from(
      input.matchAll(rule.regex),
    ).entries()) {
      const start = match.index ?? index;
      if (!validBuiltInMatch(rule, match[0], input, start)) continue;

      matches.push({
        id: `${rule.matchIdPrefix}-${start}-${index}`,
        kind: rule.kind,
        value: match[0],
        start,
        end: start + match[0].length,
      });
    }
  }

  matches.sort((a, b) => a.start - b.start || b.end - a.end);

  // Replace only validated spans. Applying the regex again would mask invalid cards.
  let redactedText = "";
  let cursor = 0;
  for (const match of matches) {
    if (match.start < cursor) continue;
    redactedText +=
      input.slice(cursor, match.start) + `[${match.kind.toUpperCase()}]`;
    cursor = match.end;
  }
  redactedText += input.slice(cursor);

  return { backend: "regex" as const, matches, redactedText };
}

/** Legacy checksums are evidence, not a veto: newer IDs use random serials.
 * See Presidio KrRrnRecognizer/KrFrnRecognizer for the legacy weights and fallback.
 */
export function koreanRegistrationValidation(
  value: string,
): "legacy-checksum" | "possible-modern" | "invalid" {
  if (!/^[0-9]{6}-?[1-8][0-9]{6}$/.test(value)) return "invalid";
  const digits = value.replace(/-/g, "");
  const gender = Number(digits[6]);
  const year =
    (gender === 1 || gender === 2 || gender === 5 || gender === 6
      ? 1900
      : 2000) + Number(digits.slice(0, 2));
  const month = Number(digits.slice(2, 4));
  const day = Number(digits.slice(4, 6));
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  )
    return "invalid";
  const sum = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5].reduce(
    (sum, weight, i) => sum + Number(digits[i]) * weight,
    0,
  );
  const expected = ((gender <= 4 ? 11 : 13) - (sum % 11)) % 10;
  return expected === Number(digits[12])
    ? "legacy-checksum"
    : "possible-modern";
}
