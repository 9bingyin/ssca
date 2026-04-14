import { AppError } from "../errors";

const BUILTIN_PROXY_NAMES = new Set([
  "DIRECT",
  "REJECT",
  "REJECT-DROP",
  "COMPATIBLE",
  "PASS",
  "GLOBAL",
]);

const SUPPORTED_GROUP_TYPES = new Set([
  "select",
  "url-test",
  "fallback",
  "load-balance",
]);

const SUPPORTED_RULE_TYPES = new Set([
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "DOMAIN-REGEX",
  "DOMAIN-WILDCARD",
  "GEOSITE",
  "GEOIP",
  "SRC-GEOIP",
  "IP-ASN",
  "SRC-IP-ASN",
  "IP-CIDR",
  "IP-CIDR6",
  "SRC-IP-CIDR",
  "IP-SUFFIX",
  "SRC-IP-SUFFIX",
  "SRC-PORT",
  "DST-PORT",
  "IN-PORT",
  "DSCP",
  "PROCESS-NAME",
  "PROCESS-PATH",
  "PROCESS-NAME-REGEX",
  "PROCESS-PATH-REGEX",
  "PROCESS-NAME-WILDCARD",
  "PROCESS-PATH-WILDCARD",
  "NETWORK",
  "UID",
  "IN-TYPE",
  "IN-USER",
  "IN-NAME",
  "SUB-RULE",
  "AND",
  "OR",
  "NOT",
  "RULE-SET",
  "MATCH",
]);

interface ParsedRulePayload {
  type: string;
  payload: string;
  target: string;
}

export function validateMihomoConfig(config: Record<string, unknown>): void {
  const proxies = expectArray(config.proxies, "proxies");
  const groups = expectArray(config["proxy-groups"], "proxy-groups");
  const rules = expectArray(config.rules, "rules");

  const proxyNames = validateProxies(proxies);
  const groupNames = validateGroups(groups, proxyNames);
  validateRules(
    rules,
    new Set([...proxyNames, ...groupNames, ...BUILTIN_PROXY_NAMES]),
  );
}

function validateProxies(proxies: unknown[]): Set<string> {
  const names = new Set<string>();
  for (const [index, proxy] of proxies.entries()) {
    if (!isRecord(proxy)) {
      throw new AppError(`proxy ${index}: format invalid`, 500);
    }

    const name = expectString(proxy.name, `proxy ${index}: missing name`);
    const type = expectString(proxy.type, `proxy ${index}: missing type`);
    if (!name.trim() || !type.trim()) {
      throw new AppError(`proxy ${index}: format invalid`, 500);
    }
    if (BUILTIN_PROXY_NAMES.has(name) || names.has(name)) {
      throw new AppError(`proxy ${name} is the duplicate name`, 500);
    }

    names.add(name);
  }

  return names;
}

function validateGroups(
  groups: unknown[],
  proxyNames: Set<string>,
): Set<string> {
  const groupNames = new Set<string>();
  const references = new Map<string, string[]>();

  for (const [index, group] of groups.entries()) {
    if (!isRecord(group)) {
      throw new AppError(`proxy group ${index}: format invalid`, 500);
    }

    const name = expectString(group.name, `proxy group ${index}: missing name`);
    const type = expectString(group.type, `proxy group ${index}: missing type`);
    if (!SUPPORTED_GROUP_TYPES.has(type)) {
      throw new AppError(
        `proxy group[${index}]: unsupported type: ${type}`,
        500,
      );
    }
    if (
      BUILTIN_PROXY_NAMES.has(name) ||
      proxyNames.has(name) ||
      groupNames.has(name)
    ) {
      throw new AppError(`proxy group ${name}: the duplicate name`, 500);
    }

    const members = expectArray(
      group.proxies,
      `proxy group[${index}]: \`use\` or \`proxies\` missing`,
    );
    if (members.length === 0) {
      throw new AppError(
        `proxy group[${index}]: ${name}: \`use\` or \`proxies\` missing`,
        500,
      );
    }

    if (type !== "select") {
      expectString(group.url, `proxy group[${index}]: ${name}: missing url`);
      const interval = group.interval;
      if (
        typeof interval !== "number" ||
        !Number.isFinite(interval) ||
        interval <= 0
      ) {
        throw new AppError(
          `proxy group[${index}]: ${name}: invalid interval`,
          500,
        );
      }
    }

    groupNames.add(name);
    references.set(
      name,
      members.map((member, memberIndex) => {
        const memberName = expectString(
          member,
          `proxy group[${index}]: ${name}: member ${memberIndex} format invalid`,
        );
        return memberName;
      }),
    );
  }

  const allNames = new Set([
    ...proxyNames,
    ...groupNames,
    ...BUILTIN_PROXY_NAMES,
  ]);
  for (const [groupName, members] of references.entries()) {
    for (const member of members) {
      if (!allNames.has(member)) {
        throw new AppError(
          `proxy group ${groupName}: '${member}' not found`,
          500,
        );
      }
    }
  }

  detectProxyGroupCycles(references, groupNames);
  return groupNames;
}

function detectProxyGroupCycles(
  references: Map<string, string[]>,
  groupNames: Set<string>,
): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();

  for (const groupName of groupNames) {
    walk(groupName);
  }

  function walk(groupName: string): void {
    if (visited.has(groupName)) {
      return;
    }
    if (visiting.has(groupName)) {
      throw new AppError(
        `proxy group ${groupName}: circular dependency detected`,
        500,
      );
    }

    visiting.add(groupName);
    for (const member of references.get(groupName) ?? []) {
      if (groupNames.has(member)) {
        walk(member);
      }
    }
    visiting.delete(groupName);
    visited.add(groupName);
  }
}

function validateRules(rules: unknown[], validTargets: Set<string>): void {
  for (const [index, rule] of rules.entries()) {
    const line = expectString(rule, `rules[${index}] format invalid`);
    const parsed = parseRulePayload(line);

    if (!parsed.target) {
      throw new AppError(
        `rules[${index}] [${line}] error: format invalid`,
        500,
      );
    }
    if (!SUPPORTED_RULE_TYPES.has(parsed.type)) {
      throw new AppError(
        `rules[${index}] [${line}] error: unsupported rule type: ${parsed.type}`,
        500,
      );
    }
    if (parsed.type !== "MATCH" && !parsed.payload) {
      throw new AppError(
        `rules[${index}] [${line}] error: missing subsequent parameters: ${parsed.type}`,
        500,
      );
    }
    if (parsed.type !== "SUB-RULE" && !validTargets.has(parsed.target)) {
      throw new AppError(
        `rules[${index}] [${line}] error: proxy [${parsed.target}] not found`,
        500,
      );
    }
  }
}

function parseRulePayload(ruleRaw: string): ParsedRulePayload {
  const items = ruleRaw.split(",").map((item) => item.trim());
  const type = (items[0] ?? "").toUpperCase();
  let payload = "";
  let target = "";

  if (items.length <= 1) {
    return { type, payload, target };
  }

  switch (type) {
    case "MATCH":
      target = items[1] ?? "";
      break;
    case "NOT":
    case "OR":
    case "AND":
    case "SUB-RULE":
    case "DOMAIN-REGEX":
    case "PROCESS-NAME-REGEX":
    case "PROCESS-PATH-REGEX": {
      const last = items.at(-1) ?? "";
      target = last;
      payload = items.slice(1, -1).join(",");
      break;
    }
    default:
      payload = items[1] ?? "";
      target = items[2] ?? "";
      break;
  }

  return { type, payload, target };
}

function expectArray(value: unknown, message: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new AppError(`${message} format invalid`, 500);
  }
  return value;
}

function expectString(value: unknown, message: string): string {
  if (typeof value !== "string") {
    throw new AppError(message, 500);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
