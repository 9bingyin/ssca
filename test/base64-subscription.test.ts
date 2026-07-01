import { describe, expect, test } from "bun:test";
import fs from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { serializeBase64Subscription } from "../src/serializers/base64-subscription";
import { validateBase64SubscriptionProxy } from "../src/validators";

function decodeBase64Subscription(value: string): string[] {
  return Buffer.from(value, "base64")
    .toString("utf8")
    .split("\n")
    .filter(Boolean);
}

describe("serializeBase64Subscription", () => {
  test("serializes supported proxies from official mihomo fixture", async () => {
    const fixturePath = path.resolve("test/fixtures/mihomo.config.yaml");
    const fixture = YAML.parse(await fs.readFile(fixturePath, "utf8")) as {
      proxies: Record<string, unknown>[];
    };

    const wantedNames = new Set([
      "socks",
      "ss1",
      "ss2",
      "ss3",
      "vmess",
      "vmess-h2",
      "vmess-grpc",
      "vless-tcp",
      "vless-vision",
      "vless-encryption",
      "vless-reality-vision",
      "vless-reality-grpc",
      "vless-ws",
      "vless-xhttp",
      "trojan",
      "trojan-grpc",
      "trojan-ws",
      "hysteria2",
      "wg",
      "tuic",
      "anytls",
    ]);

    const proxies = fixture.proxies
      .filter((proxy) => wantedNames.has(String(proxy.name)))
      .map((proxy) => normalizeFixtureProxy(proxy));

    const result = serializeBase64Subscription(proxies);
    const lines = decodeBase64Subscription(result);

    expect(lines).toHaveLength(wantedNames.size);
    expect(lines.some((line) => line.startsWith("socks://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("ss://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("vmess://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("vless://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("trojan://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("hysteria2://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("wireguard://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("tuic://"))).toBe(true);
    expect(lines.some((line) => line.startsWith("anytls://"))).toBe(true);
  });

  test("serializes supported proxy types to share links", () => {
    const result = serializeBase64Subscription([
      {
        name: "HK SS",
        type: "ss",
        server: "1.1.1.1",
        port: 2300,
        cipher: "chacha20-ietf-poly1305",
        password: "pass",
      },
      {
        name: "WS VMess",
        type: "vmess",
        server: "vmess.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        alterId: 0,
        cipher: "auto",
        tls: true,
        network: "ws",
        servername: "vmess.example.com",
        "client-fingerprint": "chrome",
        "ws-opts": {
          path: "/ray",
          headers: {
            Host: "edge.example.com",
          },
        },
      },
      {
        name: "Reality VLESS",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "grpc",
        tls: true,
        servername: "cdn.example.com",
        "client-fingerprint": "chrome",
        "grpc-opts": {
          "grpc-service-name": "grpc",
        },
        "reality-opts": {
          "public-key": "pubkey",
          "short-id": "abcd1234",
        },
      },
      {
        name: "Trojan WS",
        type: "trojan",
        server: "trojan.example.com",
        port: 443,
        password: "secret",
        network: "ws",
        sni: "trojan.example.com",
        "ws-opts": {
          path: "/trojan",
          headers: {
            Host: "trojan.example.com",
          },
        },
      },
      {
        name: "Hy2",
        type: "hysteria2",
        server: "hy2.example.com",
        port: 443,
        password: "hy2pass",
        sni: "hy2.example.com",
        obfs: "salamander",
        "obfs-password": "mask",
        ports: "2000-3000",
      },
      {
        name: "Tuic",
        type: "tuic",
        server: "tuic.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        password: "tuicpass",
        sni: "tuic.example.com",
        "congestion-controller": "bbr",
      },
      {
        name: "WG",
        type: "wireguard",
        server: "162.159.192.1",
        port: 2480,
        ip: "172.16.0.2",
        ipv6: "fd01:5ca1:ab1e:80fa:ab85:6eea:213f:f4a5",
        "public-key": "pubkey",
        "private-key": "privkey",
        reserved: "U4An",
        mtu: 1280,
      },
      {
        name: "Socks",
        type: "socks5",
        server: "socks.example.com",
        port: 1080,
        username: "user",
        password: "pass",
      },
      {
        name: "AnyTLS",
        type: "anytls",
        server: "anytls.example.com",
        port: 443,
        password: "anypass",
        sni: "anytls.example.com",
      },
    ]);

    const lines = decodeBase64Subscription(result);

    expect(lines).toHaveLength(9);
    expect(lines[0]).toStartWith("ss://");
    expect(lines[1]).toStartWith("vmess://");
    expect(lines[2]).toContain("vless://");
    expect(lines[2]).toContain("security=reality");
    expect(lines[3]).toContain("trojan://");
    expect(lines[4]).toContain("hysteria2://");
    expect(lines[4]).toContain("obfs-password=mask");
    expect(lines[5]).toContain("tuic://");
    expect(lines[5]).toContain("congestion_control=bbr");
    expect(lines[6]).toContain("wireguard://");
    expect(lines[6]).toContain(
      "address=172.16.0.2%2Cfd01%3A5ca1%3Aab1e%3A80fa%3Aab85%3A6eea%3A213f%3Af4a5",
    );
    expect(lines[7]).toContain("socks://");
    expect(lines[8]).toContain("anytls://");

    const vmessPayload = JSON.parse(
      Buffer.from(lines[1].slice("vmess://".length), "base64").toString("utf8"),
    ) as Record<string, string>;
    expect(vmessPayload.net).toBe("ws");
    expect(vmessPayload.host).toBe("edge.example.com");
    expect(vmessPayload.path).toBe("/ray");
    expect(vmessPayload.tls).toBe("tls");
  });

  test("supports shadowsocks plugin serialization", () => {
    const result = serializeBase64Subscription([
      {
        name: "SS WS",
        type: "ss",
        server: "ss.example.com",
        port: 443,
        cipher: "chacha20-ietf-poly1305",
        password: "pass",
        plugin: "v2ray-plugin",
        "plugin-opts": {
          mode: "websocket",
          tls: true,
          host: "cdn.example.com",
          path: "/ws",
        },
      },
    ]);

    const [line] = decodeBase64Subscription(result);
    expect(line).toContain(
      "plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws%3Btls",
    );
  });

  test("covers commented transport and tls combinations derived from official fixture", () => {
    const result = serializeBase64Subscription([
      {
        name: "VMess WS TLS",
        type: "vmess",
        server: "vmess.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        alterId: 0,
        cipher: "auto",
        network: "ws",
        tls: true,
        servername: "vmess.example.com",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
          path: "/path",
          headers: { Host: "v2ray.com" },
        },
      },
      {
        name: "VMess HTTP",
        type: "vmess",
        server: "vmess.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        alterId: 0,
        cipher: "auto",
        network: "http",
        "http-opts": {
          path: ["/", "/video"],
          headers: { Host: ["http.example.com"] },
        },
      },
      {
        name: "VLESS WS TLS",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "ws",
        tls: true,
        servername: "example.com",
        "client-fingerprint": "chrome",
        "skip-cert-verify": true,
        "ws-opts": {
          path: "/",
          headers: { Host: "example.com" },
        },
      },
      {
        name: "Trojan WS TLS",
        type: "trojan",
        server: "trojan.example.com",
        port: 443,
        password: "secret",
        network: "ws",
        sni: "example.com",
        "skip-cert-verify": true,
        "ws-opts": {
          path: "/path",
          headers: { Host: "example.com" },
        },
      },
      {
        name: "Hy2 Salamander",
        type: "hysteria2",
        server: "server.com",
        port: 443,
        password: "yourpassword",
        sni: "server.com",
        "skip-cert-verify": true,
        alpn: ["h3"],
        obfs: "salamander",
        "obfs-password": "yourpassword",
        ports: "1000,2000-3000,5000",
      },
      {
        name: "WG Reserved Array",
        type: "wireguard",
        server: "162.159.192.1",
        port: 2480,
        ip: "172.16.0.2",
        "public-key": "pubkey",
        "private-key": "privkey",
        reserved: [209, 98, 59],
      },
      {
        name: "AnyTLS TLS Query",
        type: "anytls",
        server: "1.2.3.4",
        port: 443,
        password: "pass",
        sni: "example.com",
        alpn: ["h2", "http/1.1"],
        tls: true,
        "skip-cert-verify": true,
      },
    ]);

    const lines = decodeBase64Subscription(result);
    const vmessWs = parseVmess(lines[0]!);
    const vmessHttp = parseVmess(lines[1]!);

    expect(vmessWs.net).toBe("ws");
    expect(vmessWs.path).toBe("/path");
    expect(vmessWs.host).toBe("v2ray.com");
    expect(vmessWs.tls).toBe("tls");
    expect(vmessWs.insecure).toBe("1");

    expect(vmessHttp.net).toBe("http");
    expect(vmessHttp.host).toBe("http.example.com");
    expect(vmessHttp.path).toBe("/,/video");

    expect(lines[2]).toContain("type=ws");
    expect(lines[2]).toContain("path=%2F");
    expect(lines[2]).toContain("host=example.com");
    expect(lines[2]).toContain("security=tls");

    expect(lines[3]).toContain("type=ws");
    expect(lines[3]).toContain("path=%2Fpath");
    expect(lines[3]).toContain("sni=example.com");

    expect(lines[4]).toContain("mport=1000%2C2000-3000%2C5000");
    expect(lines[4]).toContain("obfs=salamander");
    expect(lines[4]).toContain("alpn=h3");

    expect(lines[5]).toContain("reserved=209%2C98%2C59");
    expect(lines[6]).toContain("security=tls");
    expect(lines[6]).toContain("alpn=h2%2Chttp%2F1.1");
    expect(lines[6]).toContain("type=tcp");
    expect(lines[6]).toContain("headerType=none");
  });

  test("aligns anytls query defaults with v2rayN toUri behavior", () => {
    const result = serializeBase64Subscription([
      {
        name: "AnyTLS Default",
        type: "anytls",
        server: "1.2.3.4",
        port: 443,
        password: "pass",
      },
      {
        name: "AnyTLS WS TLS",
        type: "anytls",
        server: "1.2.3.4",
        port: 443,
        password: "pass",
        tls: true,
        sni: "example.com",
        "skip-cert-verify": true,
        alpn: ["h2"],
        network: "ws",
        "ws-opts": {
          path: "/edge",
          headers: { Host: "cdn.example.com" },
        },
      },
    ]);

    const [defaultLine, wsLine] = decodeBase64Subscription(result);
    expect(defaultLine).toContain("security=none");
    expect(defaultLine).toContain("type=tcp");
    expect(defaultLine).toContain("headerType=none");
    expect(defaultLine).not.toContain("alpn=");
    expect(defaultLine).not.toContain("insecure=");

    expect(wsLine).toContain("security=tls");
    expect(wsLine).toContain("sni=example.com");
    expect(wsLine).toContain("alpn=h2");
    expect(wsLine).toContain("insecure=1");
    expect(wsLine).toContain("allowInsecure=1");
    expect(wsLine).toContain("type=ws");
    expect(wsLine).toContain("host=cdn.example.com");
    expect(wsLine).toContain("path=%2Fedge");
  });

  test("does not emit tls-only query fields for vless reality", () => {
    const result = serializeBase64Subscription([
      {
        name: "Reality VLESS",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "grpc",
        tls: true,
        servername: "cdn.example.com",
        alpn: ["h2"],
        "skip-cert-verify": true,
        "client-fingerprint": "chrome",
        "grpc-opts": {
          authority: "grpc-authority.example.com",
          "grpc-service-name": "grpc",
        },
        "reality-opts": {
          "public-key": "pubkey",
          "short-id": "abcd1234",
        },
      },
    ]);

    const [line] = decodeBase64Subscription(result);
    expect(line).toContain("security=reality");
    expect(line).toContain("pbk=pubkey");
    expect(line).toContain("sid=abcd1234");
    expect(line).toContain("authority=grpc-authority.example.com");
    expect(line).toContain("serviceName=grpc");
    expect(line).not.toContain("alpn=");
    expect(line).not.toContain("insecure=");
    expect(line).not.toContain("allowInsecure=");
  });

  test("normalizes vmess security aliases for v2rayN compatibility", () => {
    const result = serializeBase64Subscription([
      {
        name: "VMess Alias",
        type: "vmess",
        server: "vmess.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        alterId: 0,
        cipher: "chacha20-ietf-poly1305",
      },
      {
        name: "VMess Unknown",
        type: "vmess",
        server: "vmess.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        alterId: 0,
        cipher: "unsupported-cipher",
      },
    ]);

    const [aliasLine, fallbackLine] = decodeBase64Subscription(result);

    expect(parseVmess(aliasLine!).scy).toBe("chacha20-poly1305");
    expect(parseVmess(fallbackLine!).scy).toBe("auto");
  });

  test("serializes vless reality, packet encoding and websocket metadata", () => {
    const result = serializeBase64Subscription([
      {
        name: "VLESS WS Metadata",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "ws",
        tls: true,
        servername: "cdn.example.com",
        "client-fingerprint": "chrome",
        xudp: true,
        "ws-opts": {
          path: "/ws",
          headers: { Host: "edge.example.com" },
          "max-early-data": 2048,
          "early-data-header-name": "X-Early-Data",
        },
        "reality-opts": {
          "public-key": "pubkey",
          "short-id": "abcd1234",
          "_spider-x": "/spider",
        },
      },
    ]);

    const [line] = decodeBase64Subscription(result);
    const params = new URL(line!).searchParams;

    expect(params.get("security")).toBe("reality");
    expect(params.get("pbk")).toBe("pubkey");
    expect(params.get("sid")).toBe("abcd1234");
    expect(params.get("spx")).toBe("/spider");
    expect(params.get("packetEncoding")).toBe("xudp");
    expect(params.get("type")).toBe("ws");
    expect(params.get("host")).toBe("edge.example.com");
    expect(params.get("path")).toBe("/ws");
    expect(params.get("ed")).toBe("2048");
    expect(params.get("eh")).toBe("X-Early-Data");
  });

  test("serializes vless transport details learned from Sub-Store", () => {
    const result = serializeBase64Subscription([
      {
        name: "VLESS HTTPUpgrade",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "ws",
        "ws-opts": {
          path: "/upgrade",
          headers: { Host: "edge.example.com" },
          "v2ray-http-upgrade": true,
          "v2ray-http-upgrade-fast-open": true,
          "max-early-data": 2560,
        },
      },
      {
        name: "VLESS gRPC",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "grpc",
        "grpc-opts": {
          "grpc-service-name": "svc",
          "_grpc-type": "gun",
          "_grpc-authority": "grpc-authority.example.com",
        },
      },
      {
        name: "VLESS HTTP",
        type: "vless",
        server: "vless.example.com",
        port: 443,
        uuid: "1386f85e-657b-4d6e-9d56-78badb75e1fd",
        network: "http",
        "http-opts": {
          method: "POST",
          path: ["/api"],
          headers: { Host: ["http.example.com"] },
        },
      },
    ]);

    const [httpUpgradeLine, grpcLine, httpLine] =
      decodeBase64Subscription(result);
    const httpUpgrade = new URL(httpUpgradeLine!).searchParams;
    const grpc = new URL(grpcLine!).searchParams;
    const http = new URL(httpLine!).searchParams;

    expect(httpUpgrade.get("type")).toBe("httpupgrade");
    expect(httpUpgrade.get("path")).toBe("/upgrade?ed=2560");
    expect(httpUpgrade.has("ed")).toBe(false);

    expect(grpc.get("type")).toBe("grpc");
    expect(grpc.get("serviceName")).toBe("svc");
    expect(grpc.get("mode")).toBe("gun");
    expect(grpc.get("authority")).toBe("grpc-authority.example.com");

    expect(http.get("type")).toBe("http");
    expect(http.get("method")).toBe("POST");
    expect(http.get("path")).toBe("/api");
    expect(http.get("host")).toBe("http.example.com");
  });

  test("serializes shadowsocks plugin compatibility flags", () => {
    const result = serializeBase64Subscription([
      {
        name: "SS Plugin Extended",
        type: "ss",
        server: "ss.example.com",
        port: 443,
        cipher: "chacha20-ietf-poly1305",
        password: "pass",
        "udp-over-tcp": true,
        tfo: true,
        plugin: "v2ray-plugin",
        "plugin-opts": {
          mode: "websocket",
          tls: true,
          host: "cdn.example.com",
          path: "/ws",
          sni: "sni.example.com",
          "skip-cert-verify": true,
          mux: 1,
        },
      },
    ]);

    const [line] = decodeBase64Subscription(result);
    const params = new URL(line!).searchParams;
    const plugin = params.get("plugin") ?? "";

    expect(plugin).toContain("v2ray-plugin");
    expect(plugin).toContain("mode=websocket");
    expect(plugin).toContain("host=cdn.example.com");
    expect(plugin).toContain("path=/ws");
    expect(plugin).toContain("tls");
    expect(plugin).toContain("sni=sni.example.com");
    expect(plugin).toContain("skip-cert-verify=true");
    expect(plugin).toContain("mux=1");
    expect(params.get("uot")).toBe("1");
    expect(params.get("tfo")).toBe("1");
  });
});

describe("validateBase64SubscriptionProxy", () => {
  test("rejects unsupported official fixture proxies", async () => {
    const fixturePath = path.resolve("test/fixtures/mihomo.config.yaml");
    const fixture = YAML.parse(await fs.readFile(fixturePath, "utf8")) as {
      proxies: Record<string, unknown>[];
    };

    const wantedNames = new Set([
      "http",
      "snell",
      "ss4-shadow-tls",
      "ss5",
      "ss-restls-tls13",
      "ss-restls-tls12",
      "ss-kcptun",
      "hysteria",
      "masque",
      "ssr",
      "ssh-out",
      "mieru",
      "sudoku",
      "trusttunnel",
    ]);

    const proxies = fixture.proxies.filter((proxy) =>
      wantedNames.has(String(proxy.name)),
    );

    for (const proxy of proxies) {
      expect(() => validateBase64SubscriptionProxy(proxy)).toThrow();
    }
  });

  test("rejects unsupported proxy type", () => {
    expect(() =>
      validateBase64SubscriptionProxy({
        name: "HTTP",
        type: "http",
        server: "example.com",
        port: 443,
      }),
    ).toThrow("cannot be converted");
  });

  test("rejects unsupported shadowsocks plugin", () => {
    expect(() =>
      validateBase64SubscriptionProxy({
        name: "SS",
        type: "ss",
        server: "1.1.1.1",
        port: 443,
        cipher: "chacha20-ietf-poly1305",
        password: "pass",
        plugin: "shadow-tls",
      }),
    ).toThrow("unsupported shadowsocks plugin");
  });

  test("rejects tuic token mode", () => {
    expect(() =>
      validateBase64SubscriptionProxy({
        name: "TUIC",
        type: "tuic",
        server: "example.com",
        port: 443,
        token: "token-only",
      }),
    ).toThrow("token format is not supported");
  });

  test("accepts official tuic example when uuid and password exist", () => {
    expect(() =>
      validateBase64SubscriptionProxy({
        name: "tuic",
        type: "tuic",
        server: "www.example.com",
        port: 10443,
        token: "TOKEN",
        uuid: "00000000-0000-0000-0000-000000000001",
        password: "PASSWORD_1",
      }),
    ).not.toThrow();
  });
});

function normalizeFixtureProxy(
  proxy: Record<string, unknown>,
): Record<string, unknown> {
  const next = structuredClone(proxy);

  if (next.name === "vmess") {
    next.uuid = "1386f85e-657b-4d6e-9d56-78badb75e1fd";
    next.server = "vmess.example.com";
  }
  if (next.name === "vmess-h2" || next.name === "vmess-grpc") {
    next.uuid = "1386f85e-657b-4d6e-9d56-78badb75e1fd";
    next.server = "vmess.example.com";
  }
  if (
    next.name === "vless-tcp" ||
    next.name === "vless-vision" ||
    next.name === "vless-encryption" ||
    next.name === "vless-reality-vision" ||
    next.name === "vless-reality-grpc" ||
    next.name === "vless-ws" ||
    next.name === "vless-xhttp"
  ) {
    next.uuid = "1386f85e-657b-4d6e-9d56-78badb75e1fd";
    next.server = "vless.example.com";
  }
  if (next.name === "vless-reality-vision") {
    next["reality-opts"] = {
      "public-key": "pubkey",
      "short-id": "abcd1234",
    };
  }
  if (next.name === "vless-reality-grpc") {
    next["reality-opts"] = {
      "public-key": "pubkey",
      "short-id": "abcd1234",
    };
  }
  if (
    next.name === "trojan" ||
    next.name === "trojan-grpc" ||
    next.name === "trojan-ws"
  ) {
    next.server = "trojan.example.com";
  }
  if (next.name === "hysteria2") {
    next.server = "hy2.example.com";
  }
  if (next.name === "tuic") {
    next.server = "tuic.example.com";
  }
  if (next.name === "wg") {
    next.server = "162.159.192.1";
  }

  return next;
}

function parseVmess(line: string): Record<string, string> {
  return JSON.parse(
    Buffer.from(line.slice("vmess://".length), "base64").toString("utf8"),
  ) as Record<string, string>;
}
