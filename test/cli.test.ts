import { describe, expect, test } from "bun:test";
import path from "node:path";
import { parseCliArgs } from "../src/cli";

describe("parseCliArgs", () => {
  test("uses fixed file names under the default config directory", () => {
    const config = parseCliArgs([]);
    const configDir = path.resolve("data");

    expect(config.configDir).toBe(configDir);
    expect(config.proxiesFile).toBe(path.join(configDir, "nodes.yaml"));
    expect(config.profileIni).toBe(path.join(configDir, "profile.ini"));
    expect(config.templateFile).toBe(path.join(configDir, "mihomo.yaml"));
    expect(config.singBoxTemplateFile).toBe(
      path.join(configDir, "sing-box.json"),
    );
    expect(config.listenHost).toBe("0.0.0.0");
    expect(config.listenPort).toBe(3000);
    expect(config.cacheTtlSeconds).toBe(300);
  });

  test("accepts a positional config directory and server options", () => {
    const config = parseCliArgs([
      "fixtures/config",
      "--listen",
      "127.0.0.1:8080",
      "--cache-ttl",
      "0",
    ]);
    const configDir = path.resolve("fixtures/config");

    expect(config.configDir).toBe(configDir);
    expect(config.proxiesFile).toBe(path.join(configDir, "nodes.yaml"));
    expect(config.listenHost).toBe("127.0.0.1");
    expect(config.listenPort).toBe(8080);
    expect(config.cacheTtlSeconds).toBe(0);
  });

  test("accepts --config-dir and --profile-ini override", () => {
    const remoteProfile =
      "https://raw.githubusercontent.com/9bingyin/routes-info/refs/heads/main/profile.ini";
    const config = parseCliArgs([
      "--config-dir",
      "data",
      "--profile-ini",
      remoteProfile,
    ]);

    expect(config.configDir).toBe(path.resolve("data"));
    expect(config.profileIni).toBe(remoteProfile);
  });

  test("accepts file URL profile and rejects removed file arguments", () => {
    const fileProfile = "file:///tmp/profile.ini";
    expect(parseCliArgs(["--profile-ini", fileProfile]).profileIni).toBe(
      fileProfile,
    );
    expect(() => parseCliArgs(["--proxies-file", "nodes.yaml"])).toThrow(
      "Unknown argument",
    );
  });
});
