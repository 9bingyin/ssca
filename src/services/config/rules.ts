import { AppError } from "../../errors";
import { ResourceLoader } from "../../loaders/resource-loader";
import type { RulesetDefinition } from "../../types";

export async function compileRules(
  rulesets: RulesetDefinition[],
  loader: ResourceLoader,
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
      rules.push(attachRuleTarget(trimmed, ruleset.policy));
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
      throw new AppError(
        `GEOIP ruleset is missing country for ${ruleset.policy}`,
        500,
      );
    }
    return `GEOIP,${country},${ruleset.policy}`;
  }

  return `${inline},${ruleset.value ? `${ruleset.value},` : ""}${ruleset.policy}`;
}

function attachRuleTarget(rule: string, policy: string): string {
  const items = rule.split(",").map((item) => item.trim());
  const type = (items[0] ?? "").toUpperCase();

  if (items.length < 2) {
    throw new AppError(`Invalid remote rule line: ${rule}`, 500);
  }

  switch (type) {
    case "MATCH":
      return `MATCH,${policy}`;
    case "NOT":
    case "OR":
    case "AND":
    case "SUB-RULE":
    case "DOMAIN-REGEX":
    case "PROCESS-NAME-REGEX":
    case "PROCESS-PATH-REGEX":
      return `${type},${items.slice(1).join(",")},${policy}`;
    default: {
      const payload = items[1];
      const params = items.slice(2);
      return [type, payload, policy, ...params].join(",");
    }
  }
}
