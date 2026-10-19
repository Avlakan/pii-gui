import { describe, expect, it } from "vitest";
import { builtInRegexRules, validBuiltInMatch } from "./pii-rules";
const rule = builtInRegexRules().find((r) => r.validator === "luhn")!;
describe("credit card candidates", () => {
  it.each([
    "4111111111111111",
    "4111 1111 1111 1111",
    "4111-1111-1111-1111",
    "378282246310005",
    "4000000000000000006",
  ])("accepts synthetic %s", (value) => {
    expect(validBuiltInMatch(rule, value, value, 0)).toBe(true);
  });
  it.each([
    "4111111111111112",
    "0000000000000000",
    "1111111111111",
    "411111111111",
    "41111111111111111111",
  ])("rejects %s", (value) => {
    expect(validBuiltInMatch(rule, value, value, 0)).toBe(false);
  });
  it("does not accept a substring inside a longer digit run", () => {
    expect(
      validBuiltInMatch(rule, "4111111111111111", "94111111111111111", 1),
    ).toBe(false);
  });
});

import { filterPii } from "./pii-rules";
it("reports the complete validated span and leaves invalid cards untouched", () => {
  const result = filterPii("card 4111 1111 1111 1111");
  expect(result.matches.find((m) => m.kind === "account_number")?.value).toBe(
    "4111 1111 1111 1111",
  );
  expect(result.redactedText).toBe("card [ACCOUNT_NUMBER]");
  expect(filterPii("card 4111 1111 1111 1112").redactedText).toBe(
    "card 4111 1111 1111 1112",
  );
});
