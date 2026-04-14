import { AppError } from "../errors";

const SUPPORTED_TYPES = new Set([
  "ss",
  "socks5",
  "vmess",
  "vless",
  "trojan",
  "hysteria2",
  "tuic",
  "wireguard",
  "anytls",
]);

const SUPPORTED_NETWORKS = new Set([
  "tcp",
  "ws",
  "grpc",
  "h2",
  "http",
  "xhttp",
]);

const V2RAYN_SS_CIPHERS = new Set([
  "aes-256-gcm",
  "aes-192-gcm",
  "aes-128-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
  "none",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
  "aes-128-ctr",
  "aes-192-ctr",
  "aes-256-ctr",
  "aes-128-cfb",
  "aes-192-cfb",
  "aes-256-cfb",
  "rc4-md5",
  "chacha20-ietf",
  "xchacha20",
]);

const VLESS_FLOWS = new Set([
  "",
  "xtls-rprx-vision",
  "xtls-rprx-vision-udp443",
]);

export function validateBase64SubscriptionProxies(
  proxies: Record<string, unknown>[],
): void {
  for (const [index, proxy] of proxies.entries()) {
    validateBase64SubscriptionProxy(proxy, index);
  }
}

export function validateBase64SubscriptionProxy(
  proxy: Record<string, unknown>,
  index = 0,
): void {
  const type = requireString(proxy, "type", index);
  if (!SUPPORTED_TYPES.has(type)) {
    throw new AppError(
      `proxy[${index}]: type '${type}' cannot be converted to base64 subscription`,
      500,
    );
  }

  requireString(proxy, "name", index);
  requireString(proxy, "server", index);
  requirePort(proxy, index);

  const network = getOptionalString(proxy, "network");
  if (network && !SUPPORTED_NETWORKS.has(network)) {
    throw new AppError(
      `proxy[${index}]: unsupported network '${network}' for base64 subscription`,
      500,
    );
  }

  switch (type) {
    case "ss":
      validateShadowsocks(proxy, index);
      break;
    case "socks5":
      break;
    case "vmess":
      if (!isUuid(requireString(proxy, "uuid", index))) {
        throw new AppError(`proxy[${index}]: invalid vmess uuid`, 500);
      }
      break;
    case "vless":
      validateVless(proxy, index);
      break;
    case "trojan":
      requireString(proxy, "password", index);
      break;
    case "hysteria2":
      requireString(proxy, "password", index);
      break;
    case "tuic":
      validateTuic(proxy, index);
      break;
    case "wireguard":
      validateWireGuard(proxy, index);
      break;
    case "anytls":
      requireString(proxy, "password", index);
      break;
  }
}

function validateShadowsocks(
  proxy: Record<string, unknown>,
  index: number,
): void {
  const cipher = requireString(proxy, "cipher", index);
  requireString(proxy, "password", index);

  if (!V2RAYN_SS_CIPHERS.has(cipher)) {
    throw new AppError(
      `proxy[${index}]: unsupported shadowsocks cipher '${cipher}'`,
      500,
    );
  }

  const plugin = getOptionalString(proxy, "plugin");
  if (!plugin) {
    return;
  }

  if (plugin !== "obfs" && plugin !== "v2ray-plugin") {
    throw new AppError(
      `proxy[${index}]: unsupported shadowsocks plugin '${plugin}' for base64 subscription`,
      500,
    );
  }

  const pluginOpts = getObject(proxy, "plugin-opts", index);
  if (plugin === "obfs") {
    const mode = requireString(pluginOpts, "mode", index);
    if (mode !== "http" && mode !== "tls") {
      throw new AppError(
        `proxy[${index}]: unsupported obfs mode '${mode}' for base64 subscription`,
        500,
      );
    }
  }
}

function validateVless(proxy: Record<string, unknown>, index: number): void {
  const uuid = requireString(proxy, "uuid", index);
  if (uuid.length > 30 && !isUuid(uuid)) {
    throw new AppError(`proxy[${index}]: invalid vless uuid`, 500);
  }

  const flow = getOptionalString(proxy, "flow") ?? "";
  if (!VLESS_FLOWS.has(flow)) {
    throw new AppError(
      `proxy[${index}]: unsupported vless flow '${flow}'`,
      500,
    );
  }

  const realityOpts = getOptionalObject(proxy, "reality-opts");
  if (realityOpts && !getOptionalString(realityOpts, "public-key")) {
    throw new AppError(
      `proxy[${index}]: reality-opts.public-key is required`,
      500,
    );
  }
}

function validateTuic(proxy: Record<string, unknown>, index: number): void {
  const uuid = getOptionalString(proxy, "uuid");
  const password = getOptionalString(proxy, "password");

  if (!uuid || !password) {
    if (getOptionalString(proxy, "token")) {
      throw new AppError(
        `proxy[${index}]: tuic token format is not supported for base64 subscription`,
        500,
      );
    }
    throw new AppError(`proxy[${index}]: missing required field 'uuid'`, 500);
  }
}

function validateWireGuard(
  proxy: Record<string, unknown>,
  index: number,
): void {
  requireString(proxy, "private-key", index);
  requireString(proxy, "public-key", index);

  if (!getOptionalString(proxy, "ip") && !getOptionalString(proxy, "ipv6")) {
    throw new AppError(`proxy[${index}]: wireguard requires ip or ipv6`, 500);
  }
}

function requirePort(proxy: Record<string, unknown>, index: number): void {
  const port = proxy.port;
  if (
    typeof port !== "number" ||
    !Number.isInteger(port) ||
    port <= 0 ||
    port > 65535
  ) {
    throw new AppError(`proxy[${index}]: invalid port`, 500);
  }
}

function requireString(
  proxy: Record<string, unknown>,
  key: string,
  index: number,
): string {
  const value = getOptionalString(proxy, key);
  if (!value) {
    throw new AppError(`proxy[${index}]: missing required field '${key}'`, 500);
  }
  return value;
}

function getOptionalString(
  proxy: Record<string, unknown>,
  key: string,
): string | null {
  const value = proxy[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function getObject(
  proxy: Record<string, unknown>,
  key: string,
  index: number,
): Record<string, unknown> {
  const value = getOptionalObject(proxy, key);
  if (!value) {
    throw new AppError(
      `proxy[${index}]: missing required object '${key}'`,
      500,
    );
  }
  return value;
}

function getOptionalObject(
  proxy: Record<string, unknown>,
  key: string,
): Record<string, unknown> | null {
  const value = proxy[key];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
    value,
  );
}
