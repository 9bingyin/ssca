export type JsonRecord = Record<string, unknown>;

export interface SingBoxCompiledInput {
  proxies: JsonRecord[];
  proxyGroups: JsonRecord[];
  rules: string[];
}

export interface ConvertedRules {
  rules: JsonRecord[];
  final: string;
  ruleSets: JsonRecord[];
}
