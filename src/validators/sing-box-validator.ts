import { AppError } from "../errors";

const TOP_LEVEL_FIELDS = new Set([
  "$schema",
  "log",
  "dns",
  "ntp",
  "certificate",
  "endpoints",
  "inbounds",
  "outbounds",
  "route",
  "services",
  "experimental",
]);

const OUTBOUND_TYPES = new Set([
  "direct",
  "block",
  "socks",
  "http",
  "shadowsocks",
  "vmess",
  "trojan",
  "hysteria",
  "vless",
  "shadowtls",
  "tuic",
  "hysteria2",
  "anytls",
  "ssh",
  "selector",
  "urltest",
  "naive",
]);

const ENDPOINT_TYPES = new Set(["wireguard", "tailscale"]);

const RULE_CONDITION_FIELDS = new Set([
  "inbound",
  "ip_version",
  "network",
  "auth_user",
  "protocol",
  "client",
  "domain",
  "domain_suffix",
  "domain_keyword",
  "domain_regex",
  "geosite",
  "source_geoip",
  "geoip",
  "source_ip_cidr",
  "source_ip_is_private",
  "ip_cidr",
  "ip_is_private",
  "source_port",
  "source_port_range",
  "port",
  "port_range",
  "process_name",
  "process_path",
  "process_path_regex",
  "package_name",
  "user",
  "user_id",
  "clash_mode",
  "network_type",
  "network_is_expensive",
  "network_is_constrained",
  "interface_address",
  "network_interface_address",
  "default_interface_address",
  "wifi_ssid",
  "wifi_bssid",
  "preferred_by",
  "rule_set",
  "rule_set_ip_cidr_match_source",
  "rule_set_ipcidr_match_source",
  "invert",
]);

const RULE_ACTION_FIELDS = new Set([
  "action",
  "outbound",
  "override_address",
  "override_port",
  "network_strategy",
  "fallback_delay",
  "udp_disable_domain_unmapping",
  "udp_connect",
  "udp_timeout",
  "tls_fragment",
  "tls_fragment_fallback_delay",
  "tls_record_fragment",
]);

const LOGICAL_RULE_FIELDS = new Set([
  "type",
  "mode",
  "rules",
  "invert",
  ...RULE_ACTION_FIELDS,
]);

const DEFAULT_RULE_FIELDS = new Set([
  "type",
  ...RULE_CONDITION_FIELDS,
  ...RULE_ACTION_FIELDS,
]);

export function validateSingBoxConfig(config: Record<string, unknown>): void {
  validateKnownFields(config, TOP_LEVEL_FIELDS, "sing-box config");
  const endpoints = expectOptionalArray(config.endpoints, "endpoints");
  const outbounds = expectOptionalArray(config.outbounds, "outbounds");
  const tags = validateOutboundAndEndpointTags(outbounds, endpoints);
  validateRoute(config.route, tags);
}

function validateOutboundAndEndpointTags(
  outbounds: unknown[],
  endpoints: unknown[],
): Set<string> {
  const tags = new Set<string>();

  for (const [index, outbound] of outbounds.entries()) {
    const record = expectRecord(outbound, `outbounds[${index}] format invalid`);
    const type = expectString(record.type, `outbounds[${index}]: missing type`);
    if (!OUTBOUND_TYPES.has(type)) {
      throw new AppError(
        `outbounds[${index}]: unknown outbound type: ${type}`,
        500,
      );
    }
    const tag = getTag(record, index);
    addUniqueTag(tags, tag);
  }

  for (const [index, endpoint] of endpoints.entries()) {
    const record = expectRecord(endpoint, `endpoints[${index}] format invalid`);
    const type = expectString(record.type, `endpoints[${index}]: missing type`);
    if (!ENDPOINT_TYPES.has(type)) {
      throw new AppError(
        `endpoints[${index}]: unknown endpoint type: ${type}`,
        500,
      );
    }
    const tag = getTag(record, index);
    addUniqueTag(tags, tag);
  }

  validateOutboundReferences(outbounds, tags);
  return tags;
}

function validateOutboundReferences(
  outbounds: unknown[],
  tags: Set<string>,
): void {
  for (const [index, outbound] of outbounds.entries()) {
    const record = expectRecord(outbound, `outbounds[${index}] format invalid`);
    const type = `${record.type}`;
    if (type !== "selector" && type !== "urltest") {
      continue;
    }

    const members = expectArray(
      record.outbounds,
      `outbounds[${index}]: missing outbounds`,
    );
    if (members.length === 0) {
      throw new AppError(`outbounds[${index}]: missing outbounds`, 500);
    }
    for (const [memberIndex, member] of members.entries()) {
      const tag = expectString(
        member,
        `outbounds[${index}].outbounds[${memberIndex}] format invalid`,
      );
      if (!tags.has(tag)) {
        throw new AppError(
          `outbounds[${index}].outbounds[${memberIndex}]: outbound not found: ${tag}`,
          500,
        );
      }
    }
  }
}

function validateRoute(route: unknown, tags: Set<string>): void {
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

function validateKnownFields(
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

function getTag(record: Record<string, unknown>, index: number): string {
  return typeof record.tag === "string" && record.tag ? record.tag : `${index}`;
}

function addUniqueTag(tags: Set<string>, tag: string): void {
  if (tags.has(tag)) {
    throw new AppError(`duplicate outbound/endpoint tag: ${tag}`, 500);
  }
  tags.add(tag);
}

function expectOptionalArray(value: unknown, path: string): unknown[] {
  if (value === undefined) {
    return [];
  }
  return expectArray(value, `${path} format invalid`);
}

function expectArray(value: unknown, message: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new AppError(message, 500);
  }
  return value;
}

function expectRecord(
  value: unknown,
  message: string,
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AppError(message, 500);
  }
  return value as Record<string, unknown>;
}

function expectString(value: unknown, message: string): string {
  if (typeof value !== "string") {
    throw new AppError(message, 500);
  }
  return value;
}
