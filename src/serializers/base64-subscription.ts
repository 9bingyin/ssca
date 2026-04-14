import { AppError } from "../errors";
import { validateBase64SubscriptionProxies } from "../validators";

const DEFAULT_VMESS_CIPHER = "auto";
const DEFAULT_VLESS_ENCRYPTION = "none";
const SUPPORTED_NETWORKS = new Set([
  "tcp",
  "ws",
  "grpc",
  "h2",
  "http",
  "xhttp",
]);

export function serializeBase64Subscription(
  proxies: Record<string, unknown>[],
): string {
  validateBase64SubscriptionProxies(proxies);

  const lines = proxies.map((proxy) => serializeProxy(proxy));
  return Buffer.from(lines.join("\n"), "utf8").toString("base64");
}

function serializeProxy(proxy: Record<string, unknown>): string {
  const type = getString(proxy, "type");

  switch (type) {
    case "ss":
      return serializeShadowsocks(proxy);
    case "socks5":
      return serializeSocks5(proxy);
    case "vmess":
      return serializeVmess(proxy);
    case "vless":
      return serializeVless(proxy);
    case "trojan":
      return serializeTrojan(proxy);
    case "hysteria2":
      return serializeHysteria2(proxy);
    case "tuic":
      return serializeTuic(proxy);
    case "wireguard":
      return serializeWireGuard(proxy);
    case "anytls":
      return serializeAnytls(proxy);
    default:
      throw new AppError(
        `Unsupported proxy type for base64 target: ${type}`,
        500,
      );
  }
}

function serializeShadowsocks(proxy: Record<string, unknown>): string {
  const server = getString(proxy, "server");
  const port = getPort(proxy);
  const cipher = getString(proxy, "cipher");
  const password = getString(proxy, "password");
  const userInfo = encodeBase64(`${cipher}:${password}`, true);
  const query = new URLSearchParams();
  const plugin = getOptionalString(proxy, "plugin");

  if (plugin === "obfs") {
    const pluginOpts = getObject(proxy, "plugin-opts");
    const parts = ["obfs-local"];
    parts.push(`obfs=${getString(pluginOpts, "mode")}`);
    const host = getOptionalString(pluginOpts, "host");
    if (host) {
      parts.push(`obfs-host=${host}`);
    }
    query.set("plugin", parts.join(";"));
  } else if (plugin === "v2ray-plugin") {
    const pluginOpts = getObject(proxy, "plugin-opts");
    const parts = ["v2ray-plugin"];
    const mode = getOptionalString(pluginOpts, "mode") ?? "websocket";
    parts.push(`mode=${mode}`);

    const host = getOptionalString(pluginOpts, "host");
    if (host) {
      parts.push(`host=${host}`);
    }

    const path = getOptionalString(pluginOpts, "path");
    if (path) {
      parts.push(`path=${escapeV2RayPluginPath(path)}`);
    }

    if (getBoolean(pluginOpts, "tls") || getBoolean(proxy, "tls")) {
      parts.push("tls");
    }

    query.set("plugin", parts.join(";"));
  }

  return buildUri(
    "ss",
    `${userInfo}@${formatAuthority(server, port)}`,
    query,
    proxy,
  );
}

function serializeSocks5(proxy: Record<string, unknown>): string {
  const server = getString(proxy, "server");
  const port = getPort(proxy);
  const username = getOptionalString(proxy, "username") ?? "";
  const password = getOptionalString(proxy, "password") ?? "";
  const userInfo = encodeBase64(`${username}:${password}`, true);

  return buildUri(
    "socks",
    `${userInfo}@${formatAuthority(server, port)}`,
    new URLSearchParams(),
    proxy,
  );
}

function serializeVmess(proxy: Record<string, unknown>): string {
  const network = normalizeNetwork(getOptionalString(proxy, "network"));
  const wsOpts = getOptionalObject(proxy, "ws-opts");
  const grpcOpts = getOptionalObject(proxy, "grpc-opts");
  const h2Opts = getOptionalObject(proxy, "h2-opts");
  const httpOpts = getOptionalObject(proxy, "http-opts");
  const xhttpOpts = getOptionalObject(proxy, "xhttp-opts");
  const tls = getBoolean(proxy, "tls");
  const servername =
    getOptionalString(proxy, "servername") ??
    getOptionalString(proxy, "sni") ??
    "";

  const payload: Record<string, unknown> = {
    v: "2",
    ps: getName(proxy),
    add: getString(proxy, "server"),
    port: getPort(proxy).toString(),
    id: getString(proxy, "uuid"),
    aid: getNumber(proxy, "alterId") ?? 0,
    scy: getOptionalString(proxy, "cipher") ?? DEFAULT_VMESS_CIPHER,
    net: network,
    type: resolveVmessType(proxy, network),
    host: "",
    path: "",
    tls: tls ? "tls" : "",
    sni: servername,
    alpn: stringifyAlpn(getOptionalUnknown(proxy, "alpn")),
    fp: getOptionalString(proxy, "client-fingerprint") ?? "",
    insecure: booleanToBinary(getBoolean(proxy, "skip-cert-verify")),
  };

  if (network === "ws") {
    payload.host = getHeaderHost(wsOpts);
    payload.path = getOptionalString(wsOpts, "path") ?? "/";
  } else if (network === "grpc") {
    payload.host = getOptionalString(proxy, "servername") ?? "";
    payload.path = getOptionalString(grpcOpts, "grpc-service-name") ?? "";
  } else if (network === "h2") {
    payload.host = stringifyHostList(h2Opts?.host);
    payload.path = getOptionalString(h2Opts, "path") ?? "/";
  } else if (network === "http") {
    payload.host = stringifyHeaderValue(httpOpts?.headers, "Host");
    payload.path = stringifyPathList(httpOpts?.path);
  } else if (network === "xhttp") {
    payload.host = getOptionalString(xhttpOpts, "host") ?? "";
    payload.path = getOptionalString(xhttpOpts, "path") ?? "/";
  }

  return `vmess://${encodeBase64(JSON.stringify(payload))}`;
}

function serializeVless(proxy: Record<string, unknown>): string {
  const query = buildUriQuery(proxy, true, null);
  query.set(
    "encryption",
    getOptionalString(proxy, "encryption") ?? DEFAULT_VLESS_ENCRYPTION,
  );

  const flow = getOptionalString(proxy, "flow");
  if (flow) {
    query.set("flow", flow);
  }

  return buildUri(
    "vless",
    `${encodeURIComponent(getString(proxy, "uuid"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function serializeTrojan(proxy: Record<string, unknown>): string {
  const query = buildUriQuery(proxy, true, null);
  const flow = getOptionalString(proxy, "flow");
  if (flow) {
    query.set("flow", flow);
  }

  return buildUri(
    "trojan",
    `${encodeURIComponent(getString(proxy, "password"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function serializeHysteria2(proxy: Record<string, unknown>): string {
  const query = new URLSearchParams();
  applyLiteSecurityQuery(proxy, query);

  const ports = getOptionalString(proxy, "ports");
  if (ports) {
    query.set("mport", ports.replaceAll(":", "-"));
  }

  const obfs = getOptionalString(proxy, "obfs");
  if (obfs === "salamander") {
    query.set("obfs", "salamander");
  }

  const obfsPassword = getOptionalString(proxy, "obfs-password");
  if (obfsPassword) {
    query.set("obfs-password", obfsPassword);
  }

  const pinSha256 = getOptionalString(proxy, "fingerprint");
  if (pinSha256) {
    query.set("pinSHA256", pinSha256.split(",")[0] ?? pinSha256);
  }

  return buildUri(
    "hysteria2",
    `${encodeURIComponent(getString(proxy, "password"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function serializeTuic(proxy: Record<string, unknown>): string {
  const query = new URLSearchParams();
  applyLiteSecurityQuery(proxy, query);

  const congestionControl = getOptionalString(proxy, "congestion-controller");
  if (congestionControl) {
    query.set("congestion_control", congestionControl);
  }

  const uuid = getString(proxy, "uuid");
  const password = getString(proxy, "password");

  return buildUri(
    "tuic",
    `${encodeURIComponent(uuid)}:${encodeURIComponent(password)}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function serializeWireGuard(proxy: Record<string, unknown>): string {
  const query = new URLSearchParams();
  query.set("publickey", getString(proxy, "public-key"));

  const reserved = getReserved(proxy);
  if (reserved) {
    query.set("reserved", reserved);
  }

  const addresses = [
    getOptionalString(proxy, "ip"),
    getOptionalString(proxy, "ipv6"),
  ]
    .filter((value): value is string => Boolean(value))
    .join(",");
  if (addresses) {
    query.set("address", addresses);
  }

  const mtu = getNumber(proxy, "mtu");
  if (typeof mtu === "number") {
    query.set("mtu", `${mtu}`);
  }

  return buildUri(
    "wireguard",
    `${encodeURIComponent(getString(proxy, "private-key"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function serializeAnytls(proxy: Record<string, unknown>): string {
  const query = buildUriQuery(proxy, true, "none");

  return buildUri(
    "anytls",
    `${encodeURIComponent(getString(proxy, "password"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}

function buildUriQuery(
  proxy: Record<string, unknown>,
  includeV2RayTransport: boolean,
  securityDefault: string | null,
): URLSearchParams {
  const query = new URLSearchParams();
  const network = normalizeNetwork(getOptionalString(proxy, "network"));
  const tls = getBoolean(proxy, "tls");
  const realityOpts = getOptionalObject(proxy, "reality-opts");
  const servername =
    getOptionalString(proxy, "servername") ?? getOptionalString(proxy, "sni");
  const alpn = stringifyAlpn(getOptionalUnknown(proxy, "alpn"));
  const clientFingerprint = getOptionalString(proxy, "client-fingerprint");
  const skipCertVerify = getBoolean(proxy, "skip-cert-verify");
  const tlsFingerprint = getOptionalString(proxy, "fingerprint");

  if (realityOpts) {
    query.set("security", "reality");
  } else if (tls) {
    query.set("security", "tls");
  } else if (securityDefault !== null) {
    query.set("security", securityDefault);
  }

  if (servername) {
    query.set("sni", servername);
  }
  if (clientFingerprint) {
    query.set("fp", clientFingerprint);
  }
  if (tlsFingerprint) {
    query.set("pcs", tlsFingerprint);
  }

  if (tls && !realityOpts) {
    if (alpn) {
      query.set("alpn", alpn);
    }
    query.set("insecure", booleanToBinary(skipCertVerify));
    query.set("allowInsecure", booleanToBinary(skipCertVerify));
  }

  if (realityOpts) {
    query.set("pbk", getString(realityOpts, "public-key"));
    const shortId = getOptionalString(realityOpts, "short-id");
    if (shortId) {
      query.set("sid", shortId);
    }
  }

  if (!includeV2RayTransport) {
    return query;
  }

  query.set("type", network);

  const wsOpts = getOptionalObject(proxy, "ws-opts");
  const grpcOpts = getOptionalObject(proxy, "grpc-opts");
  const h2Opts = getOptionalObject(proxy, "h2-opts");
  const httpOpts = getOptionalObject(proxy, "http-opts");
  const xhttpOpts = getOptionalObject(proxy, "xhttp-opts");

  if (network === "tcp") {
    query.set("headerType", "none");
  } else if (network === "ws") {
    const host = getHeaderHost(wsOpts);
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(wsOpts, "path") ?? "/");
  } else if (network === "grpc") {
    const authority =
      getOptionalString(grpcOpts, "authority") ??
      getOptionalString(proxy, "servername");
    if (authority) {
      query.set("authority", authority);
    }

    const serviceName = getOptionalString(grpcOpts, "grpc-service-name");
    if (serviceName) {
      query.set("serviceName", serviceName);
    }
  } else if (network === "h2") {
    const host = stringifyHostList(h2Opts?.host);
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(h2Opts, "path") ?? "/");
  } else if (network === "http") {
    const host = stringifyHeaderValue(httpOpts?.headers, "Host");
    if (host) {
      query.set("host", host);
    }
    const path = stringifyPathList(httpOpts?.path);
    if (path) {
      query.set("path", path);
    }
  } else if (network === "xhttp") {
    const host = getOptionalString(xhttpOpts, "host");
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(xhttpOpts, "path") ?? "/");
    const mode = getOptionalString(xhttpOpts, "mode");
    if (mode) {
      query.set("mode", mode);
    }
  }

  return query;
}

function resolveVmessType(
  proxy: Record<string, unknown>,
  network: string,
): string {
  if (network === "grpc") {
    return (
      getOptionalString(getOptionalObject(proxy, "grpc-opts"), "mode") ?? "none"
    );
  }
  if (network === "xhttp") {
    return (
      getOptionalString(getOptionalObject(proxy, "xhttp-opts"), "mode") ??
      "none"
    );
  }
  return getOptionalString(proxy, "headerType") ?? "none";
}

function applyLiteSecurityQuery(
  proxy: Record<string, unknown>,
  query: URLSearchParams,
): void {
  const sni =
    getOptionalString(proxy, "sni") ?? getOptionalString(proxy, "servername");
  if (sni) {
    query.set("sni", sni);
  }

  const alpn = stringifyAlpn(getOptionalUnknown(proxy, "alpn"));
  if (alpn) {
    query.set("alpn", alpn);
  }

  if (getBoolean(proxy, "skip-cert-verify")) {
    query.set("insecure", "1");
    query.set("allowInsecure", "1");
  } else {
    query.set("insecure", "0");
    query.set("allowInsecure", "0");
  }
}

function buildUri(
  scheme: string,
  authority: string,
  query: URLSearchParams,
  proxy: Record<string, unknown>,
): string {
  const serializedQuery = query.toString();
  const remark = encodeURIComponent(getName(proxy));
  return `${scheme}://${authority}${serializedQuery ? `?${serializedQuery}` : ""}#${remark}`;
}

function getName(proxy: Record<string, unknown>): string {
  return getString(proxy, "name");
}

function getPort(proxy: Record<string, unknown>): number {
  const port = getNumber(proxy, "port");
  if (typeof port !== "number") {
    throw new AppError("Proxy port must be a number", 500);
  }
  return port;
}

function getReserved(proxy: Record<string, unknown>): string | null {
  const reserved = proxy.reserved;
  if (typeof reserved === "string" && reserved.trim()) {
    return reserved;
  }
  if (Array.isArray(reserved)) {
    return reserved.map((value) => `${value}`).join(",");
  }
  return null;
}

function formatAuthority(server: string, port: number): string {
  if (
    server.includes(":") &&
    !server.startsWith("[") &&
    !server.endsWith("]")
  ) {
    return `[${server}]:${port}`;
  }
  return `${server}:${port}`;
}

function escapeV2RayPluginPath(path: string): string {
  return path
    .replaceAll("\\", "\\\\")
    .replaceAll("=", "\\=")
    .replaceAll(",", "\\,");
}

function normalizeNetwork(network: string | null): string {
  const resolved = network ?? "tcp";
  if (!SUPPORTED_NETWORKS.has(resolved)) {
    throw new AppError(
      `Unsupported network for base64 target: ${resolved}`,
      500,
    );
  }
  return resolved;
}

function getString(
  object: Record<string, unknown> | null | undefined,
  key: string,
): string {
  const value = getOptionalString(object, key);
  if (!value) {
    throw new AppError(`Missing required string field: ${key}`, 500);
  }
  return value;
}

function getOptionalString(
  object: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function getNumber(
  object: Record<string, unknown> | null | undefined,
  key: string,
): number | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function getBoolean(
  object: Record<string, unknown> | null | undefined,
  key: string,
): boolean {
  if (!object) {
    return false;
  }
  return object[key] === true;
}

function getObject(
  object: Record<string, unknown> | null | undefined,
  key: string,
): Record<string, unknown> {
  const value = getOptionalObject(object, key);
  if (!value) {
    throw new AppError(`Missing required object field: ${key}`, 500);
  }
  return value;
}

function getOptionalObject(
  object: Record<string, unknown> | null | undefined,
  key: string,
): Record<string, unknown> | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function getOptionalUnknown(
  object: Record<string, unknown> | null | undefined,
  key: string,
): unknown {
  return object?.[key];
}

function getHeaderHost(object: Record<string, unknown> | null): string {
  if (!object) {
    return "";
  }
  return stringifyHeaderValue(object.headers, "Host");
}

function stringifyHeaderValue(value: unknown, key: string): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "";
  }
  const record = value as Record<string, unknown>;
  const headerValue = record[key];
  if (typeof headerValue === "string") {
    return headerValue;
  }
  if (Array.isArray(headerValue)) {
    return headerValue
      .filter((item): item is string => typeof item === "string")
      .join(",");
  }
  return "";
}

function stringifyHostList(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .filter((item): item is string => typeof item === "string")
      .join(",");
  }
  return "";
}

function stringifyPathList(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .filter((item): item is string => typeof item === "string")
      .join(",");
  }
  return "";
}

function stringifyAlpn(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .filter((item): item is string => typeof item === "string")
      .join(",");
  }
  return "";
}

function booleanToBinary(value: boolean): string {
  return value ? "1" : "0";
}

function encodeBase64(value: string, removePadding = false): string {
  const encoded = Buffer.from(value, "utf8").toString("base64");
  return removePadding ? encoded.replace(/=+$/u, "") : encoded;
}
