import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { ConfigBuilder } from "../src/services/config-builder";
import { ResourceLoader } from "../src/loaders/resource-loader";
import type { AppConfig } from "../src/types";

const tempRoot = path.join(os.tmpdir(), "ssca-tests");

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
`
    );
    await fs.writeFile(directFile, "DOMAIN-SUFFIX,example.com\n");
    await fs.writeFile(
      profileFile,
      `[custom]
ruleset=直连规则,${directFile}
ruleset=默认规则,[]FINAL
custom_proxy_group=代理规则\`select\`[]DIRECT\`.*
`
    );
    await fs.writeFile(
      templateFile,
      `mixed-port: 7890
mode: rule
proxies: []
proxy-groups: []
rules: []
`
    );

    const config: AppConfig = {
      listenHost: "127.0.0.1",
      listenPort: 3000,
      proxiesFile,
      profileIni: profileFile,
      templateFile,
      cacheTtlSeconds: 300
    };

    const output = await new ConfigBuilder(config, new ResourceLoader(300)).build();

    expect(output).toContain("mixed-port: 7890");
    expect(output).toContain("- name: HK\n");
    expect(output).toContain("- name: HK 02");
    expect(output).not.toContain("HK dup");
    expect(output).toContain("DOMAIN-SUFFIX,example.com,直连规则");
    expect(output).toContain("MATCH,默认规则");
  });
});
