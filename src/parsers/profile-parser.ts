import { AppError } from "../errors";
import type {
  ParsedProfile,
  ProxyGroupDefinition,
  ProxyGroupType,
  RulesetDefinition,
} from "../types";

const SUPPORTED_GROUP_TYPES = new Set<ProxyGroupType>([
  "select",
  "url-test",
  "fallback",
  "load-balance",
]);

export function parseProfileIni(content: string): ParsedProfile {
  const rulesets: RulesetDefinition[] = [];
  const proxyGroups: ProxyGroupDefinition[] = [];
  let inCustomSection = false;

  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }

    if (line.startsWith("[") && line.endsWith("]")) {
      inCustomSection = line === "[custom]";
      continue;
    }

    if (!inCustomSection) {
      continue;
    }

    if (line.startsWith("ruleset=")) {
      rulesets.push(parseRuleset(line.slice("ruleset=".length)));
      continue;
    }

    if (line.startsWith("custom_proxy_group=")) {
      proxyGroups.push(
        parseProxyGroup(line.slice("custom_proxy_group=".length)),
      );
    }
  }

  if (rulesets.length === 0) {
    throw new AppError("No ruleset found in [custom] section", 500);
  }

  return { rulesets, proxyGroups };
}

function parseRuleset(value: string): RulesetDefinition {
  const parts = value.split(",");
  if (parts.length < 2) {
    throw new AppError(`Invalid ruleset definition: ${value}`, 500);
  }

  const policy = parts[0]?.trim();
  const source = parts[1]?.trim();
  if (!policy || !source) {
    throw new AppError(`Invalid ruleset definition: ${value}`, 500);
  }

  return {
    policy,
    source,
    value: parts.slice(2).join(",").trim() || undefined,
  };
}

function parseProxyGroup(value: string): ProxyGroupDefinition {
  const parts = value.split("`").map((item) => item.trim());
  if (parts.length < 3) {
    throw new AppError(`Invalid custom_proxy_group definition: ${value}`, 500);
  }

  const [name, typeText, ...rest] = parts;
  const type = typeText as ProxyGroupType;
  if (!SUPPORTED_GROUP_TYPES.has(type)) {
    throw new AppError(`Unsupported proxy group type: ${typeText}`, 500);
  }

  if (type === "select") {
    return {
      name,
      type,
      rawMembers: rest,
    };
  }

  if (rest.length < 3) {
    throw new AppError(
      `Proxy group ${name} is missing url-test parameters`,
      500,
    );
  }

  const testUrl = rest.at(-2);
  const intervalConfig = rest.at(-1);
  if (!testUrl || !intervalConfig) {
    throw new AppError(
      `Proxy group ${name} is missing test url or interval`,
      500,
    );
  }

  const intervals = intervalConfig.split(",").map((item) => item.trim());
  const intervalSeconds = Number.parseInt(intervals[0] ?? "", 10);
  if (!Number.isInteger(intervalSeconds) || intervalSeconds <= 0) {
    throw new AppError(`Invalid interval for proxy group ${name}`, 500);
  }

  return {
    name,
    type,
    rawMembers: rest.slice(0, -2),
    testUrl,
    intervalSeconds,
    timeout: parseOptionalInteger(intervals[1]),
    tolerance: parseOptionalInteger(intervals[2]),
  };
}

function parseOptionalInteger(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) ? parsed : undefined;
}
