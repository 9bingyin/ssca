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

  test("accepts --config-dir and rejects legacy file arguments", () => {
    expect(parseCliArgs(["--config-dir", "data"]).configDir).toBe(
      path.resolve("data"),
    );
    expect(() => parseCliArgs(["--proxies-file", "nodes.yaml"])).toThrow(
      "Unknown argument",
    );
  });
});
