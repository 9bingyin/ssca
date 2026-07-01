import { AppError } from "../../errors";

const SUPPORTED_NETWORKS = new Set([
  "tcp",
  "ws",
  "grpc",
  "h2",
  "http",
  "xhttp",
]);

export type ProxyRecord = Record<string, unknown>;

export function getName(proxy: ProxyRecord): string {
  return getString(proxy, "name");
}

export function getPort(proxy: ProxyRecord): number {
  const port = getNumber(proxy, "port");
  if (typeof port !== "number") {
    throw new AppError("Proxy port must be a number", 500);
  }
  return port;
}

export function getReserved(proxy: ProxyRecord): string | null {
  const reserved = proxy.reserved;
  if (typeof reserved === "string" && reserved.trim()) {
    return reserved;
  }
  if (Array.isArray(reserved)) {
    return reserved.map((value) => `${value}`).join(",");
  }
  return null;
}

export function formatAuthority(server: string, port: number): string {
  if (
    server.includes(":") &&
    !server.startsWith("[") &&
    !server.endsWith("]")
  ) {
    return `[${server}]:${port}`;
  }
  return `${server}:${port}`;
}

export function escapeV2RayPluginPath(path: string): string {
  return path
    .replaceAll("\\", "\\\\")
    .replaceAll("=", "\\=")
    .replaceAll(",", "\\,");
}

export function normalizeNetwork(network: string | null): string {
  const resolved = network ?? "tcp";
  if (!SUPPORTED_NETWORKS.has(resolved)) {
    throw new AppError(
      `Unsupported network for base64 target: ${resolved}`,
      500,
    );
  }
  return resolved;
}

export function getString(
  object: ProxyRecord | null | undefined,
  key: string,
): string {
  const value = getOptionalString(object, key);
  if (!value) {
    throw new AppError(`Missing required string field: ${key}`, 500);
  }
  return value;
}

export function getOptionalString(
  object: ProxyRecord | null | undefined,
  key: string,
): string | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  return typeof value === "string" && value.trim() ? value : null;
}

export function getNumber(
  object: ProxyRecord | null | undefined,
  key: string,
): number | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function getBoolean(
  object: ProxyRecord | null | undefined,
  key: string,
): boolean {
  if (!object) {
    return false;
  }
  return object[key] === true;
}

export function getObject(
  object: ProxyRecord | null | undefined,
  key: string,
): ProxyRecord {
  const value = getOptionalObject(object, key);
  if (!value) {
    throw new AppError(`Missing required object field: ${key}`, 500);
  }
  return value;
}

export function getOptionalObject(
  object: ProxyRecord | null | undefined,
  key: string,
): ProxyRecord | null {
  if (!object) {
    return null;
  }
  const value = object[key];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as ProxyRecord;
}

export function getOptionalUnknown(
  object: ProxyRecord | null | undefined,
  key: string,
): unknown {
  return object?.[key];
}

export function getHeaderHost(object: ProxyRecord | null): string {
  if (!object) {
    return "";
  }
  return stringifyHeaderValue(object.headers, "Host");
}

export function stringifyHeaderValue(value: unknown, key: string): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "";
  }
  const record = value as ProxyRecord;
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

export function stringifyHostList(value: unknown): string {
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

export function stringifyPathList(value: unknown): string {
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

export function stringifyAlpn(value: unknown): string {
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

export function booleanToBinary(value: boolean): string {
  return value ? "1" : "0";
}

export function encodeBase64(value: string, removePadding = false): string {
  const encoded = Buffer.from(value, "utf8").toString("base64");
  return removePadding ? encoded.replace(/=+$/u, "") : encoded;
}
