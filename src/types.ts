export interface AppConfig {
  listenHost: string;
  listenPort: number;
  configDir: string;
  subscriptionPath: string;
  proxiesFile: string;
  profileIni: string;
  templateFile: string;
  singBoxTemplateFile: string;
  cacheTtlSeconds: number;
}

export interface CacheEntry<T> {
  expiresAt: number;
  value: T;
}

export interface FileCacheEntry<T> {
  mtimeMs: number;
  value: T;
}

export interface ParsedProfile {
  rulesets: RulesetDefinition[];
  proxyGroups: ProxyGroupDefinition[];
}

export interface RulesetDefinition {
  policy: string;
  source: string;
  value?: string;
}

export interface ProxyGroupDefinition {
  name: string;
  type: ProxyGroupType;
  rawMembers: string[];
  icon?: string;
  testUrl?: string;
  intervalSeconds?: number;
  timeout?: number;
  tolerance?: number;
}

export type ProxyGroupType =
  "select" | "url-test" | "fallback" | "load-balance";

export interface ProxyGroupIconDefinition {
  name: string;
  url: string;
}

export interface CompiledConfig {
  proxies: Record<string, unknown>[];
  proxyGroups: Record<string, unknown>[];
  rules: string[];
}

export type OutputTarget = "mihomo" | "base64" | "sing-box";
