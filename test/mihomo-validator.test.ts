import { describe, expect, test } from "bun:test";
import { validateMihomoConfig } from "../src/validators";

describe("validateMihomoConfig", () => {
  test("accepts valid mihomo config", () => {
    expect(() =>
      validateMihomoConfig({
        proxies: [
          { name: "HK", type: "ss" },
          { name: "JP", type: "ss" },
        ],
        "proxy-groups": [
          {
            name: "自动选择",
            type: "url-test",
            proxies: ["HK", "JP"],
            url: "http://detectportal.firefox.com/success.txt",
            interval: 300,
          },
          {
            name: "代理规则",
            type: "select",
            proxies: ["自动选择", "DIRECT", "HK"],
          },
        ],
        rules: ["DOMAIN-SUFFIX,example.com,代理规则", "MATCH,代理规则"],
      }),
    ).not.toThrow();
  });

  test("rejects missing proxy group member", () => {
    expect(() =>
      validateMihomoConfig({
        proxies: [{ name: "HK", type: "ss" }],
        "proxy-groups": [
          {
            name: "代理规则",
            type: "select",
            proxies: ["不存在的组"],
          },
        ],
        rules: ["MATCH,代理规则"],
      }),
    ).toThrow("'不存在的组' not found");
  });

  test("rejects rule target not found", () => {
    expect(() =>
      validateMihomoConfig({
        proxies: [{ name: "HK", type: "ss" }],
        "proxy-groups": [
          {
            name: "代理规则",
            type: "select",
            proxies: ["HK"],
          },
        ],
        rules: ["DOMAIN-SUFFIX,example.com,不存在"],
      }),
    ).toThrow("proxy [不存在] not found");
  });
});
