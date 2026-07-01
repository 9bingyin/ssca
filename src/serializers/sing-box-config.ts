import { AppError } from "../errors";
import { normalizeVmessSecurity } from "./base64/vmess-security";

type JsonRecord = Record<string, unknown>;

const BUILTIN_OUTBOUNDS: JsonRecord[] = [
  { type: "direct", tag: "DIRECT" },
  { type: "block", tag: "REJECT" },
  { type: "block", tag: "REJECT-DROP" },
];

const SING_BOX_UTLS_FINGERPRINTS = new Set([
  "chrome",
  "firefox",
  "edge",
  "safari",
  "360",
  "qq",
  "ios",
  "android",
  "random",
  "randomized",
]);

export interface SingBoxCompiledInput {
  proxies: JsonRecord[];
  proxyGroups: JsonRecord[];
  rules: string[];
}

export function serializeSingBoxConfig(
  template: JsonRecord,
  compiled: SingBoxCompiledInput,
): string {
  const converted = convertSingBoxConfig(template, compiled);
  return `${JSON.stringify(converted, null, 2)}\n`;
}

export function convertSingBoxConfig(
  template: JsonRecord,
  compiled: SingBoxCompiledInput,
): JsonRecord {
  const proxyEntries = compiled.proxies.map(convertProxyOutbound);
  const endpointEntries = proxyEntries.filter(
    (entry) => entry.type === "wireguard",
  );
  const proxyOutbounds = proxyEntries.filter(
    (entry) => entry.type !== "wireguard",
  );
  const groupOutbounds = compiled.proxyGroups.map(convertProxyGroupOutbound);
  const { rules, final, ruleSets } = convertRules(compiled.rules);
  const routeTemplate = getRecord(template.route) ?? {};
  const templateEndpoints = getArray(template, "endpoints") as JsonRecord[];
  const templateRuleSets = getArray(routeTemplate, "rule_set") as JsonRecord[];

  return pruneEmpty({
    ...template,
    endpoints: [...templateEndpoints, ...endpointEntries],
    outbounds: [...BUILTIN_OUTBOUNDS, ...proxyOutbounds, ...groupOutbounds],
    route: {
      ...routeTemplate,
      rules,
      final,
      rule_set: [...templateRuleSets, ...ruleSets],
    },
  });
}

function convertProxyOutbound(proxy: JsonRecord): JsonRecord {
  const type = getString(proxy, "type");

  switch (type) {
    case "ss":
      return convertShadowsocks(proxy);
    case "socks5":
      return convertSocks(proxy);
    case "vmess":
      return convertVmess(proxy);
    case "vless":
      return convertVless(proxy);
    case "trojan":
      return convertTrojan(proxy);
    case "hysteria2":
      return convertHysteria2(proxy);
    case "tuic":
      return convertTuic(proxy);
    case "wireguard":
      return convertWireGuard(proxy);
    case "anytls":
      return convertAnyTLS(proxy);
    default:
      throw new AppError(
        `Unsupported proxy type for sing-box target: ${type}`,
        500,
      );
  }
}

function convertShadowsocks(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "shadowsocks",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    method: getString(proxy, "cipher"),
    password: getString(proxy, "password"),
  };

  applyDialerOptions(proxy, outbound);
  applyUdpOverTcp(proxy, outbound);
  applyShadowsocksPlugin(proxy, outbound);
  return pruneEmpty(outbound);
}

function convertSocks(proxy: JsonRecord): JsonRecord {
  if (getBoolean(proxy, "tls")) {
    throw new AppError("sing-box does not support socks5 with tls", 500);
  }

  const outbound: JsonRecord = {
    type: "socks",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    version: "5",
    username: getOptionalString(proxy, "username"),
    password: getOptionalString(proxy, "password"),
  };

  applyDialerOptions(proxy, outbound);
  applyUdpOverTcp(proxy, outbound);
  return pruneEmpty(outbound);
}

function convertVmess(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "vmess",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    security: normalizeVmessSecurity(getOptionalString(proxy, "cipher")),
    alter_id: getOptionalNumber(proxy, "alterId") ?? 0,
    tls: {
      enabled: false,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyPacketEncoding(proxy, outbound, false);
  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}

function convertVless(proxy: JsonRecord): JsonRecord {
  const encryption = getOptionalString(proxy, "encryption");
  if (encryption && encryption !== "none") {
    throw new AppError("VLESS encryption is not supported by sing-box", 500);
  }

  const flow = getOptionalString(proxy, "flow");
  if (flow && flow !== "xtls-rprx-vision") {
    throw new AppError(`sing-box does not support vless flow: ${flow}`, 500);
  }

  const outbound: JsonRecord = {
    type: "vless",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    flow,
    tls: {
      enabled: false,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyPacketEncoding(proxy, outbound, true);
  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}

function convertTrojan(proxy: JsonRecord): JsonRecord {
  if (getOptionalString(proxy, "flow")) {
    throw new AppError("sing-box does not support trojan flow", 500);
  }

  const outbound: JsonRecord = {
    type: "trojan",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}

function convertHysteria2(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "hysteria2",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  const obfs = getOptionalString(proxy, "obfs");
  if (obfs === "salamander" || obfs === "gecko") {
    outbound.obfs = pruneEmpty({
      type: obfs,
      password: getOptionalString(proxy, "obfs-password"),
    });
  }

  applyNumber(proxy, outbound, "up", "up_mbps");
  applyNumber(proxy, outbound, "down", "down_mbps");
  applyDurationSeconds(proxy, outbound, "hop-interval", "hop_interval");
  applyServerPorts(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

function convertTuic(proxy: JsonRecord): JsonRecord {
  if (getOptionalString(proxy, "token")) {
    throw new AppError("sing-box does not support TUIC v4 token mode", 500);
  }

  const outbound: JsonRecord = {
    type: "tuic",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  const congestionControl = getOptionalString(proxy, "congestion-controller");
  if (congestionControl && congestionControl !== "cubic") {
    outbound.congestion_control = congestionControl;
  }
  const relayMode = getOptionalString(proxy, "udp-relay-mode");
  if (relayMode && relayMode !== "native") {
    outbound.udp_relay_mode = relayMode;
  }
  if (getBoolean(proxy, "reduce-rtt")) {
    outbound.zero_rtt_handshake = true;
  }
  if (getBoolean(proxy, "udp-over-stream")) {
    outbound.udp_over_stream = true;
  }
  applyDurationMilliseconds(proxy, outbound, "heartbeat-interval", "heartbeat");

  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

function convertWireGuard(proxy: JsonRecord): JsonRecord {
  const peers = getArray(proxy, "peers");
  const endpoint: JsonRecord = {
    type: "wireguard",
    tag: getString(proxy, "name"),
    address: resolveWireGuardAddress(proxy),
    private_key: getString(proxy, "private-key"),
    peers: (peers.length > 0 ? peers : [{}]).map((peer) =>
      convertWireGuardPeer(getRecord(peer) ?? {}, proxy),
    ),
  };

  applyNumber(proxy, endpoint, "mtu", "mtu");
  applyDialerOptions(proxy, endpoint);
  return pruneEmpty(endpoint);
}

function convertAnyTLS(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "anytls",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyDurationSeconds(
    proxy,
    outbound,
    "idle-session-check-interval",
    "idle_session_check_interval",
  );
  applyDurationSeconds(
    proxy,
    outbound,
    "idle-session-timeout",
    "idle_session_timeout",
  );
  applyNumber(proxy, outbound, "min-idle-session", "min_idle_session");
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

function convertProxyGroupOutbound(group: JsonRecord): JsonRecord {
  const type = getString(group, "type");
  const outbounds = getArray(group, "proxies").map((item) => `${item}`);

  if (type === "select") {
    return {
      type: "selector",
      tag: getString(group, "name"),
      outbounds,
    };
  }

  if (type === "url-test" || type === "fallback" || type === "load-balance") {
    return pruneEmpty({
      type: "urltest",
      tag: getString(group, "name"),
      outbounds,
      url: getOptionalString(group, "url"),
      interval: formatDurationSeconds(getOptionalNumber(group, "interval")),
      tolerance: getOptionalNumber(group, "tolerance"),
    });
  }

  throw new AppError(
    `Unsupported proxy group type for sing-box target: ${type}`,
    500,
  );
}

function convertRules(rawRules: string[]): {
  rules: JsonRecord[];
  final: string;
  ruleSets: JsonRecord[];
} {
  const rules: JsonRecord[] = [];
  const ruleSets = new Map<string, JsonRecord>();
  let final = "DIRECT";

  for (const [index, rawRule] of rawRules.entries()) {
    const parsed = parseMihomoRule(rawRule);
    if (parsed.type === "MATCH") {
      final = parsed.target;
      continue;
    }

    const rule = convertRule(parsed, ruleSets);
    if (!rule) {
      throw new AppError(
        `Unsupported rule for sing-box target at ${index}: ${rawRule}`,
        500,
      );
    }
    rules.push(rule);
  }

  return { rules, final, ruleSets: [...ruleSets.values()] };
}

interface ParsedMihomoRule {
  type: string;
  payload: string;
  target: string;
  params: string[];
}

function parseMihomoRule(rawRule: string): ParsedMihomoRule {
  const items = rawRule.split(",").map((item) => item.trim());
  const type = (items[0] ?? "").toUpperCase();
  if (type === "MATCH") {
    return { type, payload: "", target: items[1] ?? "", params: [] };
  }
  return {
    type,
    payload: items[1] ?? "",
    target: items[2] ?? "",
    params: items.slice(3),
  };
}

function convertRule(
  rule: ParsedMihomoRule,
  ruleSets: Map<string, JsonRecord>,
): JsonRecord | null {
  const output: JsonRecord = { outbound: rule.target };

  switch (rule.type) {
    case "DOMAIN":
      output.domain = [rule.payload];
      break;
    case "DOMAIN-SUFFIX":
      output.domain_suffix = [rule.payload];
      break;
    case "DOMAIN-KEYWORD":
      output.domain_keyword = [rule.payload];
      break;
    case "DOMAIN-REGEX":
      output.domain_regex = [rule.payload];
      break;
    case "GEOSITE":
      output.rule_set = [
        ensureRemoteRuleSet(ruleSets, "geosite", rule.payload),
      ];
      break;
    case "GEOIP":
      if (rule.payload.toUpperCase() === "LAN") {
        output.ip_is_private = true;
      } else {
        output.rule_set = [
          ensureRemoteRuleSet(ruleSets, "geoip", rule.payload),
        ];
      }
      break;
    case "IP-CIDR":
    case "IP-CIDR6":
      output.ip_cidr = [rule.payload];
      break;
    case "SRC-IP-CIDR":
      output.source_ip_cidr = [rule.payload];
      break;
    case "SRC-PORT":
      applyRulePort(output, "source_port", "source_port_range", rule.payload);
      break;
    case "DST-PORT":
      applyRulePort(output, "port", "port_range", rule.payload);
      break;
    case "PROCESS-NAME":
      output.process_name = [rule.payload];
      break;
    case "PROCESS-PATH":
      output.process_path = [rule.payload];
      break;
    case "PROCESS-PATH-REGEX":
      output.process_path_regex = [rule.payload];
      break;
    case "RULE-SET":
      output.rule_set = [rule.payload];
      break;
    case "NETWORK":
      output.network = [rule.payload.toLowerCase()];
      break;
    default:
      return null;
  }

  return output;
}

function ensureRemoteRuleSet(
  ruleSets: Map<string, JsonRecord>,
  kind: "geoip" | "geosite",
  code: string,
): string {
  const normalized = code.toLowerCase();
  const tag = `${kind}-${normalized}`;
  if (!ruleSets.has(tag)) {
    const repository = kind === "geoip" ? "sing-geoip" : "sing-geosite";
    ruleSets.set(tag, {
      tag,
      type: "remote",
      format: "binary",
      url: `https://raw.githubusercontent.com/SagerNet/${repository}/rule-set/${tag}.srs`,
    });
  }
  return tag;
}

function applyRulePort(
  output: JsonRecord,
  portKey: string,
  rangeKey: string,
  value: string,
): void {
  if (/^\d+$/u.test(value)) {
    output[portKey] = [Number.parseInt(value, 10)];
    return;
  }
  output[rangeKey] = [value.replace("-", ":")];
}

function applyShadowsocksPlugin(proxy: JsonRecord, outbound: JsonRecord): void {
  const plugin = getOptionalString(proxy, "plugin");
  if (!plugin) {
    return;
  }

  const pluginOpts = getRecord(proxy["plugin-opts"]) ?? {};
  const parts: string[] = [];

  if (plugin === "obfs") {
    outbound.plugin = "obfs-local";
    parts.push(`obfs=${getString(pluginOpts, "mode")}`);
    const host = getOptionalString(pluginOpts, "host");
    if (host) parts.push(`obfs-host=${host}`);
  } else if (plugin === "v2ray-plugin") {
    outbound.plugin = "v2ray-plugin";
    const mode = getOptionalString(pluginOpts, "mode");
    if (mode) parts.push(`mode=${mode}`);
    const host = getOptionalString(pluginOpts, "host");
    if (host) parts.push(`host=${host}`);
    const path = getOptionalString(pluginOpts, "path");
    if (path) parts.push(`path=${path}`);
    if (getBoolean(pluginOpts, "tls")) parts.push("tls");
    const sni = getOptionalString(pluginOpts, "sni");
    if (sni) parts.push(`sni=${sni}`);
    if (getBoolean(pluginOpts, "skip-cert-verify")) {
      parts.push("skip-cert-verify=true");
    }
    const mux = getOptionalNumber(pluginOpts, "mux");
    if (typeof mux === "number") parts.push(`mux=${mux}`);
  } else {
    throw new AppError(
      `Unsupported shadowsocks plugin for sing-box target: ${plugin}`,
      500,
    );
  }

  outbound.plugin_opts = parts.join(";");
}

function applyTls(
  proxy: JsonRecord,
  outbound: JsonRecord,
  forceEnabled: boolean,
): void {
  const tls = getRecord(outbound.tls) ?? { enabled: false };
  if (forceEnabled || getBoolean(proxy, "tls")) {
    tls.enabled = true;
  }

  const serverName =
    getOptionalString(proxy, "servername") ??
    getOptionalString(proxy, "sni") ??
    getOptionalString(proxy, "peer");
  if (serverName) {
    tls.server_name = serverName;
  }
  if (getBoolean(proxy, "skip-cert-verify") || getBoolean(proxy, "insecure")) {
    tls.insecure = true;
  }

  const alpn = toStringArray(proxy.alpn);
  if (alpn.length > 0) {
    tls.alpn = alpn;
  }

  const realityOpts = getRecord(proxy["reality-opts"]);
  if (realityOpts) {
    tls.enabled = true;
    tls.reality = pruneEmpty({
      enabled: true,
      public_key: getOptionalString(realityOpts, "public-key"),
      short_id: getOptionalString(realityOpts, "short-id"),
    });
    tls.utls = { enabled: true };
  }

  const fingerprint = normalizeFingerprint(
    getOptionalString(proxy, "client-fingerprint"),
  );
  if (
    fingerprint &&
    !["hysteria", "hysteria2", "tuic"].includes(getString(proxy, "type"))
  ) {
    tls.utls = { ...(getRecord(tls.utls) ?? {}), enabled: true, fingerprint };
  }

  if (tls.enabled) {
    outbound.tls = pruneEmpty(tls);
  } else {
    delete outbound.tls;
  }
}

function applyV2RayTransport(proxy: JsonRecord, outbound: JsonRecord): void {
  const network = getOptionalString(proxy, "network") ?? "tcp";
  if (network === "tcp") {
    return;
  }
  if (network === "xhttp") {
    throw new AppError("sing-box does not support xhttp transport", 500);
  }

  switch (network) {
    case "ws":
      outbound.transport = buildWebSocketTransport(proxy);
      break;
    case "grpc":
      outbound.transport = buildGrpcTransport(proxy);
      break;
    case "h2":
    case "http":
      outbound.transport = buildHttpTransport(proxy, network);
      break;
    default:
      throw new AppError(
        `Unsupported network for sing-box target: ${network}`,
        500,
      );
  }
}

function buildWebSocketTransport(proxy: JsonRecord): JsonRecord {
  const wsOpts = getRecord(proxy["ws-opts"]) ?? {};
  const headers = getRecord(wsOpts.headers) ?? {};
  const isHttpUpgrade = getBoolean(wsOpts, "v2ray-http-upgrade");
  const host = stringifyHeaderValue(headers, "Host");
  const transport: JsonRecord = {
    type: isHttpUpgrade ? "httpupgrade" : "ws",
    path: getOptionalString(wsOpts, "path"),
  };

  if (isHttpUpgrade) {
    if (host) transport.host = host;
    const remainingHeaders = { ...headers };
    delete remainingHeaders.Host;
    if (Object.keys(remainingHeaders).length > 0)
      transport.headers = remainingHeaders;
  } else {
    if (Object.keys(headers).length > 0) transport.headers = headers;
    applyNumber(wsOpts, transport, "max-early-data", "max_early_data");
    const earlyDataHeader = getOptionalString(wsOpts, "early-data-header-name");
    if (earlyDataHeader) transport.early_data_header_name = earlyDataHeader;
  }

  return pruneEmpty(transport);
}

function buildGrpcTransport(proxy: JsonRecord): JsonRecord {
  const grpcOpts = getRecord(proxy["grpc-opts"]) ?? {};
  return pruneEmpty({
    type: "grpc",
    service_name: getOptionalString(grpcOpts, "grpc-service-name"),
  });
}

function buildHttpTransport(proxy: JsonRecord, network: string): JsonRecord {
  const opts =
    getRecord(proxy[network === "h2" ? "h2-opts" : "http-opts"]) ?? {};
  const headers = getRecord(opts.headers) ?? {};
  const host = network === "h2" ? opts.host : headers.Host;
  const transport: JsonRecord = {
    type: "http",
    host: toStringArray(host),
    path: firstString(opts.path),
  };

  const method = getOptionalString(opts, "method");
  if (method) transport.method = method;
  return pruneEmpty(transport);
}

function applyPacketEncoding(
  proxy: JsonRecord,
  outbound: JsonRecord,
  pointer: boolean,
): void {
  let value = getOptionalString(proxy, "packet-encoding");
  if (!value && getBoolean(proxy, "xudp")) value = "xudp";
  if (!value && getBoolean(proxy, "packet-addr")) value = "packetaddr";
  if (!value) return;

  if (value === "packet") value = "packetaddr";
  if (!["packetaddr", "xudp"].includes(value)) return;
  outbound.packet_encoding = pointer ? value : value;
}

function applyDialerOptions(proxy: JsonRecord, outbound: JsonRecord): void {
  if (getBoolean(proxy, "tfo") || getBoolean(proxy, "tcp-fast-open")) {
    outbound.tcp_fast_open = true;
  }
  const detour =
    getOptionalString(proxy, "dialer-proxy") ??
    getOptionalString(proxy, "detour");
  if (detour) outbound.detour = detour;
}

function applyUdpOverTcp(proxy: JsonRecord, outbound: JsonRecord): void {
  if (getBoolean(proxy, "uot")) {
    outbound.udp_over_tcp = { enabled: true };
  }
  if (getBoolean(proxy, "udp-over-tcp")) {
    outbound.udp_over_tcp = {
      enabled: true,
      version: getOptionalNumber(proxy, "udp-over-tcp-version") === 2 ? 2 : 1,
    };
  }
}

function convertWireGuardPeer(peer: JsonRecord, proxy: JsonRecord): JsonRecord {
  const server =
    getOptionalString(peer, "server") ?? getString(proxy, "server");
  const port = getOptionalNumber(peer, "port") ?? getPort(proxy);
  return pruneEmpty({
    address: server,
    port,
    public_key:
      getOptionalString(peer, "public-key") ??
      getOptionalString(peer, "public_key") ??
      getString(proxy, "public-key"),
    pre_shared_key:
      getOptionalString(peer, "pre-shared-key") ??
      getOptionalString(peer, "pre_shared_key") ??
      getOptionalString(proxy, "pre-shared-key"),
    allowed_ips: getArray(peer, "allowed-ips").length
      ? getArray(peer, "allowed-ips")
      : ["0.0.0.0/0"],
    reserved: toNumberArray(peer.reserved).length
      ? toNumberArray(peer.reserved)
      : toNumberArray(proxy.reserved),
  });
}

function resolveWireGuardAddress(proxy: JsonRecord): string[] {
  const explicit = getArray(proxy, "ip").map((item) => `${item}`);
  if (explicit.length > 0) return explicit;

  const ipv4 = getOptionalString(proxy, "ip");
  const ipv6 = getOptionalString(proxy, "ipv6");
  const addresses: string[] = [];
  if (ipv4) addresses.push(ipv4.includes("/") ? ipv4 : `${ipv4}/32`);
  if (ipv6) addresses.push(ipv6.includes("/") ? ipv6 : `${ipv6}/128`);
  if (addresses.length === 0) {
    throw new AppError(
      `WireGuard proxy ${getString(proxy, "name")} is missing address`,
      500,
    );
  }
  return addresses;
}

function applyServerPorts(proxy: JsonRecord, outbound: JsonRecord): void {
  const ports = getOptionalString(proxy, "ports");
  if (!ports) return;
  outbound.server_ports = ports.split(/\s*,\s*/u).map((port) => {
    const range = port.replace(/\s*-\s*/u, ":");
    return range.includes(":") ? range : `${range}:${range}`;
  });
}

function applyNumber(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalNumber(source, sourceKey);
  if (typeof value === "number") target[targetKey] = value;
}

function applyDurationSeconds(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalDurationValue(source, sourceKey);
  if (value) target[targetKey] = /^\d+$/u.test(value) ? `${value}s` : value;
}

function applyDurationMilliseconds(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalDurationValue(source, sourceKey);
  if (value) target[targetKey] = /^\d+$/u.test(value) ? `${value}ms` : value;
}

function getOptionalDurationValue(
  source: JsonRecord,
  key: string,
): string | null {
  const value = source[key];
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return `${value}`;
  }
  return getOptionalString(source, key);
}

function formatDurationSeconds(value: number | null): string | undefined {
  return typeof value === "number" ? `${value}s` : undefined;
}

function normalizeFingerprint(value: string | null): string | null {
  const normalized = value?.trim().toLowerCase();
  return normalized && SING_BOX_UTLS_FINGERPRINTS.has(normalized)
    ? normalized
    : null;
}

function stringifyHeaderValue(headers: JsonRecord, key: string): string {
  const value = headers[key];
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => `${item}`).join(",");
  return "";
}

function firstString(value: unknown): string | undefined {
  if (typeof value === "string" && value) return value;
  if (Array.isArray(value) && value.length > 0) return `${value[0]}`;
  return undefined;
}

function toStringArray(value: unknown): string[] {
  if (typeof value === "string" && value.trim())
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  if (Array.isArray(value))
    return value.map((item) => `${item}`).filter(Boolean);
  return [];
}

function toNumberArray(value: unknown): number[] {
  if (Array.isArray(value)) {
    return value
      .map((item) =>
        typeof item === "number" ? item : Number.parseInt(`${item}`, 10),
      )
      .filter((item) => Number.isSafeInteger(item) && item >= 0 && item <= 255);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => Number.parseInt(item.trim(), 10))
      .filter((item) => Number.isSafeInteger(item) && item >= 0 && item <= 255);
  }
  return [];
}

function getString(object: JsonRecord, key: string): string {
  const value = getOptionalString(object, key);
  if (!value) throw new AppError(`Missing required string field: ${key}`, 500);
  return value;
}

function getOptionalString(
  object: JsonRecord | null | undefined,
  key: string,
): string | null {
  const value = object?.[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function getPort(object: JsonRecord): number {
  const port = getOptionalNumber(object, "port");
  if (port === null || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new AppError("Proxy port must be a number between 1 and 65535", 500);
  }
  return port;
}

function getOptionalNumber(
  object: JsonRecord | null | undefined,
  key: string,
): number | null {
  const value = object?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^\d+$/u.test(value.trim()))
    return Number.parseInt(value, 10);
  return null;
}

function getBoolean(
  object: JsonRecord | null | undefined,
  key: string,
): boolean {
  return object?.[key] === true;
}

function getRecord(value: unknown): JsonRecord | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

function getArray(object: JsonRecord, key: string): unknown[] {
  const value = object[key];
  return Array.isArray(value) ? value : [];
}

function pruneEmpty<T extends JsonRecord>(record: T): T {
  for (const key of Object.keys(record)) {
    const value = record[key];
    if (value === undefined || value === null || value === "") {
      delete record[key];
      continue;
    }
    if (Array.isArray(value) && value.length === 0) {
      delete record[key];
      continue;
    }
    if (getRecord(value)) {
      pruneEmpty(value as JsonRecord);
      if (Object.keys(value as JsonRecord).length === 0) delete record[key];
    }
  }
  return record;
}
