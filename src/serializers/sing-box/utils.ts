import { AppError } from "../../errors";
import { SING_BOX_UTLS_FINGERPRINTS } from "./constants";
import type { JsonRecord } from "./types";

export function applyNumber(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalNumber(source, sourceKey);
  if (typeof value === "number") target[targetKey] = value;
}

export function applyDurationSeconds(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalDurationValue(source, sourceKey);
  if (value) target[targetKey] = /^\d+$/u.test(value) ? `${value}s` : value;
}

export function applyDurationMilliseconds(
  source: JsonRecord,
  target: JsonRecord,
  sourceKey: string,
  targetKey: string,
): void {
  const value = getOptionalDurationValue(source, sourceKey);
  if (value) target[targetKey] = /^\d+$/u.test(value) ? `${value}ms` : value;
}

export function formatDurationSeconds(
  value: number | null,
): string | undefined {
  return typeof value === "number" ? `${value}s` : undefined;
}

export function normalizeFingerprint(value: string | null): string | null {
  const normalized = value?.trim().toLowerCase();
  return normalized && SING_BOX_UTLS_FINGERPRINTS.has(normalized)
    ? normalized
    : null;
}

export function stringifyHeaderValue(headers: JsonRecord, key: string): string {
  const value = headers[key];
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => `${item}`).join(",");
  return "";
}

export function firstString(value: unknown): string | undefined {
  if (typeof value === "string" && value) return value;
  if (Array.isArray(value) && value.length > 0) return `${value[0]}`;
  return undefined;
}

export function toStringArray(value: unknown): string[] {
  if (typeof value === "string" && value.trim()) {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value.map((item) => `${item}`).filter(Boolean);
  }
  return [];
}

export function toNumberArray(value: unknown): number[] {
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

export function getString(object: JsonRecord, key: string): string {
  const value = getOptionalString(object, key);
  if (!value) throw new AppError(`Missing required string field: ${key}`, 500);
  return value;
}

export function getOptionalString(
  object: JsonRecord | null | undefined,
  key: string,
): string | null {
  const value = object?.[key];
  return typeof value === "string" && value.trim() ? value : null;
}

export function getPort(object: JsonRecord): number {
  const port = getOptionalNumber(object, "port");
  if (port === null || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new AppError("Proxy port must be a number between 1 and 65535", 500);
  }
  return port;
}

export function getOptionalNumber(
  object: JsonRecord | null | undefined,
  key: string,
): number | null {
  const value = object?.[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^\d+$/u.test(value.trim())) {
    return Number.parseInt(value, 10);
  }
  return null;
}

export function getBoolean(
  object: JsonRecord | null | undefined,
  key: string,
): boolean {
  return object?.[key] === true;
}

export function getRecord(value: unknown): JsonRecord | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;
}

export function getArray(object: JsonRecord, key: string): unknown[] {
  const value = object[key];
  return Array.isArray(value) ? value : [];
}

export function pruneEmpty<T extends JsonRecord>(record: T): T {
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
