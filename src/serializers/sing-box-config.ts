import { BUILTIN_OUTBOUNDS } from "./sing-box/constants";
import { convertProxyGroupOutbound } from "./sing-box/proxy-groups";
import { convertProxyOutbound } from "./sing-box/outbounds";
import { convertRules } from "./sing-box/rules";
import { getArray, getRecord, pruneEmpty } from "./sing-box/utils";
import type { JsonRecord, SingBoxCompiledInput } from "./sing-box/types";

export type { SingBoxCompiledInput } from "./sing-box/types";

export function serializeSingBoxConfig(
  template: JsonRecord,
  compiled: SingBoxCompiledInput,
): string {
  const converted = convertSingBoxConfig(template, compiled);
  return `${JSON.stringify(converted, null, 2)}\n`;
}

export function convertSingBoxConfig(
  template: JsonRecord,
  compiled: SingBoxCompiledInput,
): JsonRecord {
  const proxyEntries = compiled.proxies.map(convertProxyOutbound);
  const endpointEntries = proxyEntries.filter(
    (entry) => entry.type === "wireguard",
  );
  const proxyOutbounds = proxyEntries.filter(
    (entry) => entry.type !== "wireguard",
  );
  const groupOutbounds = compiled.proxyGroups.map(convertProxyGroupOutbound);
  const { rules, final, ruleSets } = convertRules(compiled.rules);
  const routeTemplate = getRecord(template.route) ?? {};
  const templateEndpoints = getArray(template, "endpoints") as JsonRecord[];
  const templateRuleSets = getArray(routeTemplate, "rule_set") as JsonRecord[];

  return pruneEmpty({
    ...template,
    endpoints: [...templateEndpoints, ...endpointEntries],
    outbounds: [...BUILTIN_OUTBOUNDS, ...proxyOutbounds, ...groupOutbounds],
    route: {
      ...routeTemplate,
      rules,
      final,
      rule_set: [...templateRuleSets, ...ruleSets],
    },
  });
}
