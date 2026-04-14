import YAML from "yaml";
import { AppError } from "../errors";
import { logWarn } from "../logger";
import { parseProfileIni } from "../parsers/profile-parser";
import { ResourceLoader } from "../loaders/resource-loader";
import type {
  AppConfig,
  CompiledConfig,
  ParsedProfile,
  ProxyGroupDefinition,
  RulesetDefinition
} from "../types";

const STATIC_POLICY_NAMES = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS"]);

export class ConfigBuilder {
  constructor(
    private readonly appConfig: AppConfig,
    private readonly loader: ResourceLoader
  ) {}

  async build(): Promise<string> {
    const proxies = await this.loadProxies();
    const profile = await this.loadProfile();
    const template = await this.loadTemplate();
    const compiled = await this.compileConfig(proxies, profile);

    if (typeof template !== "object" || template === null || Array.isArray(template)) {
      throw new AppError("Template YAML must be a mapping object", 500);
    }

    const output = {
      ...template,
      proxies: compiled.proxies,
      "proxy-groups": compiled.proxyGroups,
      rules: compiled.rules
    };

    return YAML.stringify(output, {
      lineWidth: 0
    });
  }

  private async loadProxies(): Promise<Record<string, unknown>[]> {
    const raw = await this.loader.loadText(this.appConfig.proxiesFile);
    const parsed = YAML.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new AppError("Proxies file must be a YAML object", 500);
    }

    const proxies = (parsed as { proxies?: unknown }).proxies;
    if (!Array.isArray(proxies)) {
      throw new AppError("Proxies file must contain a top-level proxies array", 500);
    }

    return normalizeProxyNames(proxies as Record<string, unknown>[]);
  }

  private async loadProfile(): Promise<ParsedProfile> {
    const raw = await this.loader.loadText(this.appConfig.profileIni);
    return parseProfileIni(raw);
  }

  private async loadTemplate(): Promise<Record<string, unknown>> {
    const raw = await this.loader.loadText(this.appConfig.templateFile);
    return YAML.parse(raw) as Record<string, unknown>;
  }

  private async compileConfig(
    proxies: Record<string, unknown>[],
    profile: ParsedProfile
  ): Promise<CompiledConfig> {
    const proxyNames = proxies
      .map((proxy) => {
        const name = proxy.name;
        return typeof name === "string" ? name : null;
      })
      .filter((name): name is string => Boolean(name));

    const groupNames = new Set(profile.proxyGroups.map((group) => group.name));

    const proxyGroups = profile.proxyGroups.map((group) =>
      compileProxyGroup(group, proxyNames, groupNames)
    );

    const rules = await compileRules(profile.rulesets, this.loader);

    return {
      proxies,
      proxyGroups,
      rules
    };
  }
}

function normalizeProxyNames(proxies: Record<string, unknown>[]): Record<string, unknown>[] {
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
      name: `${name} ${String(count + 1).padStart(2, "0")}`
    });
  }

  return normalized;
}

function stripProxyName(proxy: Record<string, unknown>): Record<string, unknown> {
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

function compileProxyGroup(
  group: ProxyGroupDefinition,
  proxyNames: string[],
  groupNames: Set<string>
): Record<string, unknown> {
  const proxies = resolveGroupMembers(group, proxyNames, groupNames);

  const result: Record<string, unknown> = {
    name: group.name,
    type: group.type,
    proxies
  };

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
  groupNames: Set<string>
): string[] {
  const members: string[] = [];
  const seen = new Set<string>();

  for (const token of group.rawMembers) {
    if (!token) {
      continue;
    }

    if (token.startsWith("[]")) {
      const explicitName = token.slice(2);
      if (!explicitName) {
        throw new AppError(`Group ${group.name} contains an empty explicit member`, 500);
      }
      if (!STATIC_POLICY_NAMES.has(explicitName) && !groupNames.has(explicitName)) {
        const hasProxy = proxyNames.includes(explicitName);
        if (!hasProxy) {
          throw new AppError(
            `Group ${group.name} references unknown member: ${explicitName}`,
            500
          );
        }
      }

      if (!seen.has(explicitName)) {
        members.push(explicitName);
        seen.add(explicitName);
      }
      continue;
    }

    const regex = new RegExp(token, "u");
    const matches = proxyNames.filter((name) => regex.test(name));
    if (matches.length === 0) {
      logWarn("Proxy group regex matched no proxies", {
        group: group.name,
        pattern: token
      });
      continue;
    }

    for (const match of matches) {
      if (!seen.has(match)) {
        members.push(match);
        seen.add(match);
      }
    }
  }

  return members;
}

async function compileRules(
  rulesets: RulesetDefinition[],
  loader: ResourceLoader
): Promise<string[]> {
  const rules: string[] = [];

  for (const ruleset of rulesets) {
    if (ruleset.source.startsWith("[]")) {
      rules.push(compileInlineRule(ruleset));
      continue;
    }

    const content = await loader.loadText(ruleset.source);
    for (const rule of content.split(/\r?\n/u)) {
      const trimmed = rule.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) {
        continue;
      }
      rules.push(`${trimmed},${ruleset.policy}`);
    }
  }

  return rules;
}

function compileInlineRule(ruleset: RulesetDefinition): string {
  const inline = ruleset.source.slice(2);
  if (inline === "FINAL") {
    return `MATCH,${ruleset.policy}`;
  }

  if (inline === "GEOIP") {
    const country = ruleset.value?.trim();
    if (!country) {
      throw new AppError(`GEOIP ruleset is missing country for ${ruleset.policy}`, 500);
    }
    return `GEOIP,${country},${ruleset.policy}`;
  }

  return `${inline},${ruleset.value ? `${ruleset.value},` : ""}${ruleset.policy}`;
}
