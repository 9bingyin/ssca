import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import YAML from "yaml";
import { ConfigBuilder } from "../src/services/config-builder";
import { ResourceLoader } from "../src/loaders/resource-loader";
import type { AppConfig } from "../src/types";

const tempRoot = path.join(os.tmpdir(), "ssca-tests");
const officialTemplateFile = path.resolve("test/fixtures/mihomo.config.yaml");

afterEach(async () => {
  await fs.rm(tempRoot, { recursive: true, force: true });
});

describe("ConfigBuilder", () => {
  test("builds mihomo config from local files", async () => {
    await fs.mkdir(tempRoot, { recursive: true });

    const proxiesFile = path.join(tempRoot, "proxies.yaml");
    const profileFile = path.join(tempRoot, "profile.ini");
    const templateFile = path.join(tempRoot, "template.yaml");
    const directFile = path.join(tempRoot, "direct.list");

    await fs.writeFile(
      proxiesFile,
      `proxies:
  - name: "HK"
    type: socks5
    server: hk.example.com
    port: 443
  - name: "HK"
    type: socks5
    server: tw.example.com
    port: 443
  - name: "HK dup"
    type: socks5
    server: hk.example.com
    port: 443
`,
    );
    await fs.writeFile(directFile, "DOMAIN-SUFFIX,example.com\n");
    await fs.writeFile(
      profileFile,
      `[custom]
ruleset=直连规则,${directFile}
ruleset=默认规则,[]FINAL
custom_proxy_group=代理规则\`select\`[]DIRECT\`.*
custom_proxy_group=直连规则\`select\`[]DIRECT\`[]代理规则
custom_proxy_group=默认规则\`select\`[]代理规则\`[]DIRECT
`,
    );
    await fs.writeFile(
      templateFile,
      `mixed-port: 7890
mode: rule
proxies: []
proxy-groups: []
rules: []
`,
    );

    const config: AppConfig = {
      listenHost: "127.0.0.1",
      listenPort: 3000,
      proxiesFile,
      profileIni: profileFile,
      templateFile,
      cacheTtlSeconds: 300,
    };

    const output = await new ConfigBuilder(
      config,
      new ResourceLoader(300),
    ).build();

    expect(output).toContain("mixed-port: 7890");
    expect(output).toContain("- name: HK\n");
    expect(output).toContain("- name: HK 02");
    expect(output).not.toContain("HK dup");
    expect(output).toContain("DOMAIN-SUFFIX,example.com,直连规则");
    expect(output).toContain("MATCH,默认规则");
  });

  test("replaces generated sections while preserving official mihomo template fields", async () => {
    await fs.mkdir(tempRoot, { recursive: true });

    const proxiesFile = path.join(tempRoot, "proxies.yaml");
    const profileFile = path.join(tempRoot, "profile.ini");

    await fs.writeFile(
      proxiesFile,
      `proxies:
  - name: "Hong Kong 01"
    type: socks5
    server: hk.example.com
    port: 443
  - name: "Tokyo 01"
    type: socks5
    server: jp.example.com
    port: 443
`,
    );
    await fs.writeFile(
      profileFile,
      `[custom]
ruleset=默认规则,[]FINAL
custom_proxy_group=代理规则\`select\`[]自动选择\`[]DIRECT\`.*
custom_proxy_group=自动选择\`url-test\`.*\`https://cp.cloudflare.com/generate_204\`300,,50
custom_proxy_group=默认规则\`select\`[]代理规则\`[]DIRECT
`,
    );

    const config: AppConfig = {
      listenHost: "127.0.0.1",
      listenPort: 3000,
      proxiesFile,
      profileIni: profileFile,
      templateFile: officialTemplateFile,
      cacheTtlSeconds: 300,
    };

    const output = await new ConfigBuilder(
      config,
      new ResourceLoader(300),
    ).build();
    const parsed = YAML.parse(output) as Record<string, unknown>;

    expect(parsed["mixed-port"]).toBe(10801);
    expect(parsed["allow-lan"]).toBe(true);
    expect(parsed["dns"]).toBeDefined();
    expect(parsed["tun"]).toBeDefined();
    expect(parsed["sniffer"]).toBeDefined();

    const proxies = parsed.proxies as Array<Record<string, unknown>>;
    const groups = parsed["proxy-groups"] as Array<Record<string, unknown>>;
    const rules = parsed.rules as string[];

    expect(proxies).toHaveLength(2);
    expect(proxies[0]?.name).toBe("Hong Kong 01");
    expect(groups.map((group) => group.name)).toEqual([
      "代理规则",
      "自动选择",
      "默认规则",
    ]);
    expect(rules.at(-1)).toBe("MATCH,默认规则");

    const serialized = JSON.stringify(parsed);
    expect(serialized).not.toContain('"name":"socks"');
    expect(serialized).not.toContain('"name":"relay"');
  });

  test("builds base64 subscription from proxies file", async () => {
    await fs.mkdir(tempRoot, { recursive: true });

    const proxiesFile = path.join(tempRoot, "proxies.yaml");
    const profileFile = path.join(tempRoot, "profile.ini");
    const templateFile = path.join(tempRoot, "template.yaml");

    await fs.writeFile(
      proxiesFile,
      `proxies:
  - name: "HK SS"
    type: ss
    server: 1.1.1.1
    port: 2300
    cipher: chacha20-ietf-poly1305
    password: pass
  - name: "Reality VLESS"
    type: vless
    server: vless.example.com
    port: 443
    uuid: 1386f85e-657b-4d6e-9d56-78badb75e1fd
    network: grpc
    tls: true
    servername: cdn.example.com
    client-fingerprint: chrome
    grpc-opts:
      grpc-service-name: grpc
    reality-opts:
      public-key: pubkey
      short-id: abcd1234
`,
    );
    await fs.writeFile(profileFile, "[custom]\nruleset=默认规则,[]FINAL\n");
    await fs.writeFile(
      templateFile,
      "proxies: []\nproxy-groups: []\nrules: []\n",
    );

    const config: AppConfig = {
      listenHost: "127.0.0.1",
      listenPort: 3000,
      proxiesFile,
      profileIni: profileFile,
      templateFile,
      cacheTtlSeconds: 300,
    };

    const output = await new ConfigBuilder(
      config,
      new ResourceLoader(300),
    ).buildBase64Subscription();

    const decoded = Buffer.from(output, "base64").toString("utf8");
    expect(decoded).toContain("ss://");
    expect(decoded).toContain("vless://");
    expect(decoded).toContain("security=reality");
  });

  test("builds sing-box config from mihomo model and rules", async () => {
    await fs.mkdir(tempRoot, { recursive: true });

    const proxiesFile = path.join(tempRoot, "proxies.yaml");
    const profileFile = path.join(tempRoot, "profile.ini");
    const templateFile = path.join(tempRoot, "template.yaml");
    const singBoxTemplateFile = path.join(tempRoot, "sing-box.json");
    const directFile = path.join(tempRoot, "direct.list");

    await fs.writeFile(
      proxiesFile,
      `proxies:
  - name: "HK SS"
    type: ss
    server: 1.1.1.1
    port: 2300
    cipher: chacha20-ietf-poly1305
    password: pass
  - name: "AnyTLS"
    type: anytls
    server: anytls.example.com
    port: 443
    password: pass
    sni: cdn.example.com
    skip-cert-verify: true
    client-fingerprint: firefox
`,
    );
    await fs.writeFile(
      directFile,
      "DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8,no-resolve\nGEOIP,CN\n",
    );
    await fs.writeFile(
      profileFile,
      `[custom]
ruleset=直连规则,${directFile}
ruleset=默认规则,[]FINAL
custom_proxy_group=代理规则\`select\`[]自动选择\`[]DIRECT\`.*
custom_proxy_group=自动选择\`url-test\`.*\`https://cp.cloudflare.com/generate_204\`300,,50
custom_proxy_group=直连规则\`select\`[]DIRECT\`[]代理规则
custom_proxy_group=默认规则\`select\`[]代理规则\`[]DIRECT
`,
    );
    await fs.writeFile(
      templateFile,
      "proxies: []\nproxy-groups: []\nrules: []\n",
    );
    await fs.writeFile(
      singBoxTemplateFile,
      JSON.stringify({
        log: { level: "info" },
        route: { auto_detect_interface: true },
      }),
    );

    const config: AppConfig = {
      listenHost: "127.0.0.1",
      listenPort: 3000,
      proxiesFile,
      profileIni: profileFile,
      templateFile,
      singBoxTemplateFile,
      cacheTtlSeconds: 300,
    };

    const output = await new ConfigBuilder(
      config,
      new ResourceLoader(300),
    ).buildSingBoxConfig();
    const parsed = JSON.parse(output) as Record<string, unknown>;
    const outbounds = parsed.outbounds as Array<Record<string, unknown>>;
    const route = parsed.route as Record<string, unknown>;
    const rules = route.rules as Array<Record<string, unknown>>;

    expect(outbounds.map((outbound) => outbound.tag)).toContain("HK SS");
    expect(outbounds.map((outbound) => outbound.tag)).toContain("代理规则");
    expect(outbounds.find((outbound) => outbound.tag === "AnyTLS")?.type).toBe(
      "anytls",
    );
    expect(rules[0]).toEqual({
      domain_suffix: ["example.com"],
      outbound: "直连规则",
    });
    expect(rules[1]).toEqual({
      ip_cidr: ["10.0.0.0/8"],
      outbound: "直连规则",
    });
    expect(rules[2]).toEqual({
      rule_set: ["geoip-cn"],
      outbound: "直连规则",
    });
    expect(route.rule_set).toEqual([
      {
        tag: "geoip-cn",
        type: "remote",
        format: "binary",
        url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
      },
    ]);
    expect(route.final).toBe("默认规则");
  });
});
