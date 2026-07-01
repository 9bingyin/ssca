import { AppError } from "../../errors";
import { logWarn } from "../../logger";
import type { ProxyGroupDefinition } from "../../types";

const STATIC_POLICY_NAMES = new Set([
  "DIRECT",
  "REJECT",
  "REJECT-DROP",
  "PASS",
  "COMPATIBLE",
  "GLOBAL",
]);

export function compileProxyGroup(
  group: ProxyGroupDefinition,
  proxyNames: string[],
  groupNames: Set<string>,
  includeIcon = false,
): Record<string, unknown> {
  const proxies = resolveGroupMembers(group, proxyNames, groupNames);

  const result: Record<string, unknown> = {
    name: group.name,
    type: group.type,
    proxies,
  };

  if (includeIcon && group.icon) {
    result.icon = group.icon;
  }
  if (group.testUrl) {
    result.url = group.testUrl;
  }
  if (group.intervalSeconds) {
    result.interval = group.intervalSeconds;
  }
  if (typeof group.timeout === "number") {
    result.timeout = group.timeout;
  }
  if (typeof group.tolerance === "number") {
    result.tolerance = group.tolerance;
  }

  return result;
}

function resolveGroupMembers(
  group: ProxyGroupDefinition,
  proxyNames: string[],
  groupNames: Set<string>,
): string[] {
  const members: string[] = [];
  const seen = new Set<string>();

  for (const token of group.rawMembers) {
    if (!token) {
      continue;
    }

    if (token.startsWith("[]")) {
      appendExplicitMember(
        group,
        token.slice(2),
        proxyNames,
        groupNames,
        seen,
        members,
      );
      continue;
    }

    appendRegexMembers(group, token, proxyNames, seen, members);
  }

  return members;
}

function appendExplicitMember(
  group: ProxyGroupDefinition,
  explicitName: string,
  proxyNames: string[],
  groupNames: Set<string>,
  seen: Set<string>,
  members: string[],
): void {
  if (!explicitName) {
    throw new AppError(
      `Group ${group.name} contains an empty explicit member`,
      500,
    );
  }

  if (!STATIC_POLICY_NAMES.has(explicitName) && !groupNames.has(explicitName)) {
    const hasProxy = proxyNames.includes(explicitName);
    if (!hasProxy) {
      throw new AppError(
        `Group ${group.name} references unknown member: ${explicitName}`,
        500,
      );
    }
  }

  if (!seen.has(explicitName)) {
    members.push(explicitName);
    seen.add(explicitName);
  }
}

function appendRegexMembers(
  group: ProxyGroupDefinition,
  token: string,
  proxyNames: string[],
  seen: Set<string>,
  members: string[],
): void {
  const regex = new RegExp(token, "u");
  const matches = proxyNames.filter((name) => regex.test(name));
  if (matches.length === 0) {
    logWarn("Proxy group regex matched no proxies", {
      group: group.name,
      pattern: token,
    });
    return;
  }

  for (const match of matches) {
    if (!seen.has(match)) {
      members.push(match);
      seen.add(match);
    }
  }
}
