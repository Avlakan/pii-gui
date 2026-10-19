import { expect, it } from "vitest";
import { filterPii, japaneseNumberValid } from "./pii-rules";
it("checks My Number synthetic vectors and mutations", () => {
  const prefix = "12345678901";
  const sum = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2].reduce(
    (s, w, i) => s + Number(prefix[i]) * w,
    0,
  );
  const digit = sum % 11 <= 1 ? 0 : 11 - (sum % 11);
  expect(japaneseNumberValid(prefix + digit, "jp_my_number")).toBe(true);
  expect(japaneseNumberValid(prefix + ((digit + 1) % 10), "jp_my_number")).toBe(
    false,
  );
  expect(
    filterPii("番号:" + prefix + digit + "です").matches.some((m) =>
      m.id.startsWith("jp-my-number"),
    ),
  ).toBe(true);
});
it("checks the tax agency's published hypothetical corporate number", () => {
  expect(japaneseNumberValid("8700110005901", "jp_corporate")).toBe(true);
  expect(japaneseNumberValid("1700110005901", "jp_corporate")).toBe(false);
});
it("requires the postal symbol and does not treat an arbitrary 3-4 run as an address", () => {
  expect(
    filterPii("〒123-4567").matches.some((m) => m.kind === "private_address"),
  ).toBe(true);
  expect(
    filterPii("123-4567").matches.some((m) => m.kind === "private_address"),
  ).toBe(false);
});
it("rejects repeated placeholders", () =>
  expect(japaneseNumberValid("000000000000", "jp_my_number")).toBe(false));
