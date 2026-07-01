import { describe, expect, test } from "bun:test";
import {
  isSubscriptionPath,
  resolveTarget,
  shouldIncludeProxyGroupIcons,
} from "../src/http";

describe("resolveTarget", () => {
  test("returns mihomo for auto target", () => {
    expect(resolveTarget("auto", "ClashforWindows/0.20")).toBe("mihomo");
    expect(resolveTarget("auto", null)).toBe("mihomo");
  });

  test("returns base64 for v2rayN user agent", () => {
    expect(resolveTarget("auto", "v2rayN/7.12.8")).toBe("base64");
    expect(resolveTarget("base64", null)).toBe("base64");
  });

  test("returns sing-box for sing-box user agent or target", () => {
    expect(resolveTarget("auto", "sing-box/1.13.14")).toBe("sing-box");
    expect(resolveTarget("sing-box", null)).toBe("sing-box");
  });

  test("throws for invalid target", () => {
    expect(() => resolveTarget("surge", null)).toThrow("Invalid target");
  });
});

describe("shouldIncludeProxyGroupIcons", () => {
  test("enables icons only for mihomo requests", () => {
    expect(
      shouldIncludeProxyGroupIcons("mihomo", new URLSearchParams("icons=true")),
    ).toBe(true);
    expect(
      shouldIncludeProxyGroupIcons("mihomo", new URLSearchParams("icon=1")),
    ).toBe(true);
    expect(
      shouldIncludeProxyGroupIcons(
        "sing-box",
        new URLSearchParams("icons=true"),
      ),
    ).toBe(false);
    expect(shouldIncludeProxyGroupIcons("mihomo", new URLSearchParams())).toBe(
      false,
    );
  });
});

describe("isSubscriptionPath", () => {
  test("uses configured path as the subscription endpoint", () => {
    expect(isSubscriptionPath("/")).toBe(true);
    expect(isSubscriptionPath("/UNjkVLTt/", "/UNjkVLTt/")).toBe(true);
    expect(isSubscriptionPath("/", "/UNjkVLTt/")).toBe(false);
    expect(isSubscriptionPath("/pull", "/UNjkVLTt/")).toBe(false);
    expect(isSubscriptionPath("/health", "/UNjkVLTt/")).toBe(false);
  });
});
