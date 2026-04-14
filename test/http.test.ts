import { describe, expect, test } from "bun:test";
import { resolveTarget } from "../src/http";

describe("resolveTarget", () => {
  test("returns mihomo for auto target", () => {
    expect(resolveTarget("auto", "ClashforWindows/0.20")).toBe("mihomo");
    expect(resolveTarget("auto", null)).toBe("mihomo");
  });

  test("throws for invalid target", () => {
    expect(() => resolveTarget("surge", null)).toThrow("Invalid target");
  });
});
