import { describe, expect, test } from "bun:test";
import { parseProfileIni } from "../src/parsers/profile-parser";

describe("parseProfileIni", () => {
  test("parses rulesets and proxy groups", () => {
    const parsed = parseProfileIni(`
[custom]
ruleset=直连规则,https://example.com/direct.list
ruleset=默认规则,[]FINAL
ruleset=直连规则,[]GEOIP,CN
custom_proxy_group=代理规则\`select\`[]自动选择\`[]DIRECT\`.*
custom_proxy_group=自动选择\`url-test\`.*\`http://detectportal.firefox.com/success.txt\`300,,50
`);

    expect(parsed.rulesets).toHaveLength(3);
    expect(parsed.proxyGroups).toHaveLength(2);
    expect(parsed.proxyGroups[1]).toEqual({
      name: "自动选择",
      type: "url-test",
      rawMembers: [".*"],
      testUrl: "http://detectportal.firefox.com/success.txt",
      intervalSeconds: 300,
      timeout: undefined,
      tolerance: 50
    });
  });
});
