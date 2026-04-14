import { describe, expect, test } from "bun:test";
import { resolveTarget } from "../src/http";

describe("resolveTarget", () => {
  test("returns mihomo for auto target", () => {
    expect(resolveTarget("auto", "ClashforWindows/0.20")).toBe("mihomo");
    expect(resolveTarget("auto", null)).toBe("mihomo");
  });

  test("returns base64 for v2rayN user agent", () => {
    expect(resolveTarget("auto", "v2rayN/7.12.8")).toBe("base64");
    expect(resolveTarget("base64", null)).toBe("base64");
  });

  test("throws for invalid target", () => {
    expect(() => resolveTarget("surge", null)).toThrow("Invalid target");
  });
});
