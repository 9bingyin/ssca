import { AppError } from "../../errors";

export function validateKnownFields(
  record: Record<string, unknown>,
  knownFields: Set<string>,
  path: string,
): void {
  for (const key of Object.keys(record)) {
    if (!knownFields.has(key)) {
      throw new AppError(`${path}: unknown field: ${key}`, 500);
    }
  }
}

export function expectOptionalArray(value: unknown, path: string): unknown[] {
  if (value === undefined) {
    return [];
  }
  return expectArray(value, `${path} format invalid`);
}

export function expectArray(value: unknown, message: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new AppError(message, 500);
  }
  return value;
}

export function expectRecord(
  value: unknown,
  message: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AppError(message, 500);
  }
  return value as Record<string, unknown>;
}

export function expectString(value: unknown, message: string): string {
  if (typeof value !== "string") {
    throw new AppError(message, 500);
  }
  return value;
}
