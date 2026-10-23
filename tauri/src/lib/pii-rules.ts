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
  validator?: "luhn";
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
    redactedText += input.slice(cursor, match.start) + `[${match.kind.toUpperCase()}]`;
    cursor = match.end;
  }
  redactedText += input.slice(cursor);

  return { backend: "regex" as const, matches, redactedText };
}
