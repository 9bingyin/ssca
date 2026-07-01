import { AppError } from "../../errors";

export function normalizeProxyNames(
  proxies: Record<string, unknown>[],
): Record<string, unknown>[] {
  const seenBySignature = new Set<string>();
  const seenByName = new Map<string, number>();
  const normalized: Record<string, unknown>[] = [];

  for (const proxy of proxies) {
    const name = proxy.name;
    if (typeof name !== "string" || !name.trim()) {
      throw new AppError("Every proxy must have a non-empty string name", 500);
    }

    const signature = stableStringify(stripProxyName(proxy));
    if (seenBySignature.has(signature)) {
      continue;
    }
    seenBySignature.add(signature);

    const count = seenByName.get(name) ?? 0;
    seenByName.set(name, count + 1);
    if (count === 0) {
      normalized.push(proxy);
      continue;
    }

    normalized.push({
      ...proxy,
      name: `${name} ${String(count + 1).padStart(2, "0")}`,
    });
  }

  return normalized;
}

function stripProxyName(
  proxy: Record<string, unknown>,
): Record<string, unknown> {
  const { name: _name, ...rest } = proxy;
  return rest;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableStringify(item)}`);
    return `{${entries.join(",")}}`;
  }

  return JSON.stringify(value);
}
