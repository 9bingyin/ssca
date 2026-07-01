import { AppError } from "../../errors";
import type { ConvertedRules, JsonRecord } from "./types";

const MERGEABLE_ARRAY_FIELDS = new Set([
  "domain",
  "domain_suffix",
  "domain_keyword",
  "domain_regex",
  "ip_cidr",
  "source_ip_cidr",
  "process_name",
  "process_path",
  "process_path_regex",
  "rule_set",
  "network",
]);

interface ParsedMihomoRule {
  type: string;
  payload: string;
  target: string;
  params: string[];
}

export function convertRules(rawRules: string[]): ConvertedRules {
  const rules: JsonRecord[] = [];
  const ruleSets = new Map<string, JsonRecord>();
  let final = "DIRECT";

  for (const [index, rawRule] of rawRules.entries()) {
    const parsed = parseMihomoRule(rawRule);
    if (parsed.type === "MATCH") {
      final = parsed.target;
      continue;
    }

    const rule = convertRule(parsed, ruleSets);
    if (!rule) {
      throw new AppError(
        `Unsupported rule for sing-box target at ${index}: ${rawRule}`,
        500,
      );
    }
    appendRule(rules, rule);
  }

  return { rules, final, ruleSets: [...ruleSets.values()] };
}

function parseMihomoRule(rawRule: string): ParsedMihomoRule {
  const items = rawRule.split(",").map((item) => item.trim());
  const type = (items[0] ?? "").toUpperCase();
  if (type === "MATCH") {
    return { type, payload: "", target: items[1] ?? "", params: [] };
  }
  return {
    type,
    payload: items[1] ?? "",
    target: items[2] ?? "",
    params: items.slice(3),
  };
}

function convertRule(
  rule: ParsedMihomoRule,
  ruleSets: Map<string, JsonRecord>,
): JsonRecord | null {
  const output: JsonRecord = { outbound: rule.target };

  switch (rule.type) {
    case "DOMAIN":
      output.domain = [rule.payload];
      break;
    case "DOMAIN-SUFFIX":
      output.domain_suffix = [rule.payload];
      break;
    case "DOMAIN-KEYWORD":
      output.domain_keyword = [rule.payload];
      break;
    case "DOMAIN-REGEX":
      output.domain_regex = [rule.payload];
      break;
    case "GEOSITE":
      output.rule_set = [ensureMetaRuleSet(ruleSets, "geosite", rule.payload)];
      break;
    case "GEOIP":
      if (rule.payload.toUpperCase() === "LAN") {
        output.ip_is_private = true;
      } else {
        output.rule_set = [ensureMetaRuleSet(ruleSets, "geoip", rule.payload)];
      }
      break;
    case "IP-CIDR":
    case "IP-CIDR6":
      output.ip_cidr = [rule.payload];
      break;
    case "SRC-IP-CIDR":
      output.source_ip_cidr = [rule.payload];
      break;
    case "SRC-PORT":
      applyRulePort(output, "source_port", "source_port_range", rule.payload);
      break;
    case "DST-PORT":
      applyRulePort(output, "port", "port_range", rule.payload);
      break;
    case "PROCESS-NAME":
      output.process_name = [rule.payload];
      break;
    case "PROCESS-PATH":
      output.process_path = [rule.payload];
      break;
    case "PROCESS-PATH-REGEX":
      output.process_path_regex = [rule.payload];
      break;
    case "RULE-SET":
      output.rule_set = [rule.payload];
      break;
    case "NETWORK":
      output.network = [rule.payload.toLowerCase()];
      break;
    default:
      return null;
  }

  return output;
}

function ensureMetaRuleSet(
  ruleSets: Map<string, JsonRecord>,
  kind: "geoip" | "geosite",
  code: string,
): string {
  const normalized = code.toLowerCase();
  const tag = `${kind}-${normalized}`;
  if (!ruleSets.has(tag)) {
    ruleSets.set(tag, {
      tag,
      type: "remote",
      format: "binary",
      url: `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/${kind}/${normalized}.srs`,
    });
  }
  return tag;
}

function appendRule(rules: JsonRecord[], rule: JsonRecord): void {
  const lastRule = rules.at(-1);
  if (lastRule && mergeRule(lastRule, rule)) {
    return;
  }
  rules.push(rule);
}

function mergeRule(target: JsonRecord, source: JsonRecord): boolean {
  if (target.outbound !== source.outbound) {
    return false;
  }

  const targetKeys = Object.keys(target).filter((key) => key !== "outbound");
  const sourceKeys = Object.keys(source).filter((key) => key !== "outbound");
  if (targetKeys.length !== 1 || sourceKeys.length !== 1) {
    return false;
  }

  const field = targetKeys[0];
  if (field !== sourceKeys[0] || !MERGEABLE_ARRAY_FIELDS.has(field)) {
    return false;
  }

  const targetValues = target[field];
  const sourceValues = source[field];
  if (!Array.isArray(targetValues) || !Array.isArray(sourceValues)) {
    return false;
  }

  targetValues.push(...sourceValues);
  return true;
}

function applyRulePort(
  output: JsonRecord,
  portKey: string,
  rangeKey: string,
  value: string,
): void {
  if (/^\d+$/u.test(value)) {
    output[portKey] = [Number.parseInt(value, 10)];
    return;
  }
  output[rangeKey] = [value.replace("-", ":")];
}
