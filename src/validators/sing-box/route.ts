import { AppError } from "../../errors";
import {
  DEFAULT_RULE_FIELDS,
  LOGICAL_RULE_FIELDS,
  RULE_ACTION_FIELDS,
} from "./constants";
import {
  expectArray,
  expectOptionalArray,
  expectRecord,
  expectString,
  validateKnownFields,
} from "./helpers";

export function validateRoute(route: unknown, tags: Set<string>): void {
  if (route === undefined) {
    return;
  }

  const record = expectRecord(route, "route format invalid");
  const rules = expectOptionalArray(record.rules, "route.rules");
  for (const [index, rule] of rules.entries()) {
    validateRule(rule, tags, `route.rules[${index}]`);
  }

  if (
    typeof record.final === "string" &&
    record.final &&
    !tags.has(record.final)
  ) {
    throw new AppError(`route.final outbound not found: ${record.final}`, 500);
  }
}

function validateRule(rule: unknown, tags: Set<string>, path: string): void {
  const record = expectRecord(rule, `${path} format invalid`);
  const type = typeof record.type === "string" ? record.type : "";

  if (type === "logical") {
    validateKnownFields(record, LOGICAL_RULE_FIELDS, path);
    validateLogicalRule(record, tags, path);
    return;
  }
  if (type && type !== "default") {
    throw new AppError(`${path}: unknown rule type: ${type}`, 500);
  }

  validateKnownFields(record, DEFAULT_RULE_FIELDS, path);
  validateDefaultRule(record, tags, path);
}

function validateDefaultRule(
  rule: Record<string, unknown>,
  tags: Set<string>,
  path: string,
): void {
  if (!hasDefaultRuleCondition(rule)) {
    throw new AppError(`${path}: missing conditions`, 500);
  }
  validateRuleAction(rule, tags, path);
}

function validateLogicalRule(
  rule: Record<string, unknown>,
  tags: Set<string>,
  path: string,
): void {
  const mode = expectString(rule.mode, `${path}: missing mode`);
  if (mode !== "and" && mode !== "or") {
    throw new AppError(`${path}: unknown logical mode: ${mode}`, 500);
  }

  const subRules = expectArray(rule.rules, `${path}: missing rules`);
  if (subRules.length === 0) {
    throw new AppError(`${path}: missing conditions`, 500);
  }
  for (const [index, subRule] of subRules.entries()) {
    validateRule(subRule, tags, `${path}.rules[${index}]`);
  }
  validateRuleAction(rule, tags, path);
}

function validateRuleAction(
  rule: Record<string, unknown>,
  tags: Set<string>,
  path: string,
): void {
  const action =
    typeof rule.action === "string" && rule.action ? rule.action : "route";
  if (
    ![
      "route",
      "route-options",
      "direct",
      "bypass",
      "reject",
      "hijack-dns",
      "sniff",
      "resolve",
    ].includes(action)
  ) {
    throw new AppError(`${path}: unknown rule action: ${action}`, 500);
  }
  if (
    (action === "route" || action === "") &&
    typeof rule.outbound !== "string"
  ) {
    throw new AppError(`${path}: missing outbound field`, 500);
  }
  if (
    typeof rule.outbound === "string" &&
    rule.outbound &&
    !tags.has(rule.outbound)
  ) {
    throw new AppError(`${path}: outbound not found: ${rule.outbound}`, 500);
  }
  if (rule.tls_fragment === true && rule.tls_record_fragment === true) {
    throw new AppError(
      `${path}: tls_fragment and tls_record_fragment are mutually exclusive`,
      500,
    );
  }
}

function hasDefaultRuleCondition(rule: Record<string, unknown>): boolean {
  const emptyRule = new Set(["type", "action", "outbound"]);
  return Object.entries(rule).some(([key, value]) => {
    if (emptyRule.has(key) || RULE_ACTION_FIELDS.has(key)) {
      return false;
    }
    if (Array.isArray(value)) {
      return value.length > 0;
    }
    return value !== undefined && value !== null && value !== "";
  });
}
