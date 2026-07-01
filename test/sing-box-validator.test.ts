import { describe, expect, test } from "bun:test";
import { validateSingBoxConfig } from "../src/validators";

describe("validateSingBoxConfig", () => {
  test("accepts valid sing-box route and outbound graph", () => {
    expect(() =>
      validateSingBoxConfig({
        outbounds: [
          { type: "direct", tag: "DIRECT" },
          { type: "block", tag: "REJECT" },
          { type: "shadowsocks", tag: "Proxy" },
          { type: "selector", tag: "Auto", outbounds: ["Proxy", "DIRECT"] },
        ],
        route: {
          rules: [
            { domain_suffix: ["example.com"], outbound: "Auto" },
            { ip_cidr: ["10.0.0.0/8"], outbound: "DIRECT" },
          ],
          final: "Auto",
        },
      }),
    ).not.toThrow();
  });

  test("rejects duplicate outbound and endpoint tags like sing-box", () => {
    expect(() =>
      validateSingBoxConfig({
        outbounds: [{ type: "direct", tag: "dup" }],
        endpoints: [{ type: "wireguard", tag: "dup" }],
      }),
    ).toThrow("duplicate outbound/endpoint tag");
  });

  test("rejects missing route conditions and unknown outbound", () => {
    expect(() =>
      validateSingBoxConfig({
        outbounds: [{ type: "direct", tag: "DIRECT" }],
        route: { rules: [{ outbound: "DIRECT" }] },
      }),
    ).toThrow("missing conditions");

    expect(() =>
      validateSingBoxConfig({
        outbounds: [{ type: "direct", tag: "DIRECT" }],
        route: { rules: [{ domain: ["example.com"], outbound: "Missing" }] },
      }),
    ).toThrow("outbound not found");
  });
});
