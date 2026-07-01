import YAML from "yaml";
import { AppError } from "../errors";
import { ResourceLoader } from "../loaders/resource-loader";
import { parseProfileIni } from "../parsers/profile-parser";
import { serializeBase64Subscription } from "../serializers/base64-subscription";
import { serializeSingBoxConfig } from "../serializers/sing-box-config";
import { validateMihomoConfig, validateSingBoxConfig } from "../validators";
import { compileProxyGroup } from "./config/proxy-groups";
import { compileRules } from "./config/rules";
import { normalizeProxyNames } from "./config/normalize-proxies";
import type { AppConfig, CompiledConfig, ParsedProfile } from "../types";

export class ConfigBuilder {
  constructor(
    private readonly appConfig: AppConfig,
    private readonly loader: ResourceLoader,
  ) {}

  async build(): Promise<string> {
    const proxies = await this.loadProxies();
    const profile = await this.loadProfile();
    const template = await this.loadTemplate();
    const compiled = await this.compileConfig(proxies, profile);

    if (
      typeof template !== "object" ||
      template === null ||
      Array.isArray(template)
    ) {
      throw new AppError("Template YAML must be a mapping object", 500);
    }

    const output = {
      ...template,
      proxies: compiled.proxies,
      "proxy-groups": compiled.proxyGroups,
      rules: compiled.rules,
    };

    validateMihomoConfig(output);

    return YAML.stringify(output, {
      lineWidth: 0,
    });
  }

  async buildBase64Subscription(): Promise<string> {
    const proxies = await this.loadProxies();
    return serializeBase64Subscription(proxies);
  }

  async buildSingBoxConfig(): Promise<string> {
    const proxies = await this.loadProxies();
    const profile = await this.loadProfile();
    const template = await this.loadSingBoxTemplate();
    const compiled = await this.compileConfig(proxies, profile);
    const output = serializeSingBoxConfig(template, compiled);
    validateSingBoxConfig(JSON.parse(output) as Record<string, unknown>);
    return output;
  }

  private async loadProxies(): Promise<Record<string, unknown>[]> {
    const raw = await this.loader.loadText(this.appConfig.proxiesFile);
    const parsed = YAML.parse(raw);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new AppError("Proxies file must be a YAML object", 500);
    }

    const proxies = (parsed as { proxies?: unknown }).proxies;
    if (!Array.isArray(proxies)) {
      throw new AppError(
        "Proxies file must contain a top-level proxies array",
        500,
      );
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

  private async loadSingBoxTemplate(): Promise<Record<string, unknown>> {
    const raw = await this.loader.loadText(this.appConfig.singBoxTemplateFile);
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new AppError(
        "sing-box template JSON must be a mapping object",
        500,
      );
    }
    return parsed as Record<string, unknown>;
  }

  private async compileConfig(
    proxies: Record<string, unknown>[],
    profile: ParsedProfile,
  ): Promise<CompiledConfig> {
    const proxyNames = proxies
      .map((proxy) => {
        const name = proxy.name;
        return typeof name === "string" ? name : null;
      })
      .filter((name): name is string => Boolean(name));

    const groupNames = new Set(profile.proxyGroups.map((group) => group.name));

    const proxyGroups = profile.proxyGroups.map((group) =>
      compileProxyGroup(group, proxyNames, groupNames),
    );

    const rules = await compileRules(profile.rulesets, this.loader);

    return {
      proxies,
      proxyGroups,
      rules,
    };
  }
}
