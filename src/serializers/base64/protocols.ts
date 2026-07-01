import { AppError } from "../../errors";
import {
  booleanToBinary,
  encodeBase64,
  escapeV2RayPluginPath,
  formatAuthority,
  getBoolean,
  getHeaderHost,
  getName,
  getNumber,
  getObject,
  getOptionalObject,
  getOptionalString,
  getOptionalUnknown,
  getPort,
  getReserved,
  getString,
  normalizeNetwork,
  stringifyAlpn,
  stringifyHeaderValue,
  stringifyHostList,
  stringifyPathList,
  type ProxyRecord,
} from "./helpers";
import {
  applyLiteSecurityQuery,
  buildUri,
  buildUriQuery,
  resolveVmessType,
} from "./query";

const DEFAULT_VMESS_CIPHER = "auto";
const DEFAULT_VLESS_ENCRYPTION = "none";

export function serializeProxy(proxy: ProxyRecord): string {
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

function serializeShadowsocks(proxy: ProxyRecord): string {
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

function serializeSocks5(proxy: ProxyRecord): string {
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

function serializeVmess(proxy: ProxyRecord): string {
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

  const payload: ProxyRecord = {
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

function serializeVless(proxy: ProxyRecord): string {
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

function serializeTrojan(proxy: ProxyRecord): string {
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

function serializeHysteria2(proxy: ProxyRecord): string {
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

function serializeTuic(proxy: ProxyRecord): string {
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

function serializeWireGuard(proxy: ProxyRecord): string {
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

function serializeAnytls(proxy: ProxyRecord): string {
  const query = buildUriQuery(proxy, true, "none");

  return buildUri(
    "anytls",
    `${encodeURIComponent(getString(proxy, "password"))}@${formatAuthority(getString(proxy, "server"), getPort(proxy))}`,
    query,
    proxy,
  );
}
