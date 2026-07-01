import path from "node:path";
import { AppError } from "./errors";
import type { AppConfig } from "./types";

const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_PORT = 3000;
const DEFAULT_TTL_SECONDS = 300;
const DEFAULT_CONFIG_DIR = "data";

const CONFIG_FILE_NAMES = {
  proxies: "nodes.yaml",
  mihomoTemplate: "mihomo.yaml",
  singBoxTemplate: "sing-box.json",
  profile: "profile.ini",
} as const;

export function parseCliArgs(argv: string[]): AppConfig {
  const options = parseOptions(argv);
  const listen = options.listen ?? `${DEFAULT_HOST}:${DEFAULT_PORT}`;
  const [listenHost, portText] = splitListen(listen);
  const listenPort = parseListenPort(portText);
  const cacheTtlSeconds = parseCacheTtl(options.cacheTtl);
  const configDir = path.resolve(options.configDir ?? DEFAULT_CONFIG_DIR);
  const profileIni =
    options.profileIni ?? path.join(configDir, CONFIG_FILE_NAMES.profile);

  return {
    listenHost,
    listenPort,
    configDir,
    proxiesFile: path.join(configDir, CONFIG_FILE_NAMES.proxies),
    profileIni,
    templateFile: path.join(configDir, CONFIG_FILE_NAMES.mihomoTemplate),
    singBoxTemplateFile: path.join(
      configDir,
      CONFIG_FILE_NAMES.singBoxTemplate,
    ),
    cacheTtlSeconds,
  };
}

interface CliOptions {
  configDir?: string;
  listen?: string;
  cacheTtl?: string;
  profileIni?: string;
}

function parseOptions(argv: string[]): CliOptions {
  const options: CliOptions = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--listen") {
      options.listen = readOptionValue(argv, ++index, token);
    } else if (token === "--cache-ttl") {
      options.cacheTtl = readOptionValue(argv, ++index, token);
    } else if (token === "--config-dir") {
      options.configDir = readOptionValue(argv, ++index, token);
    } else if (token === "--profile-ini") {
      options.profileIni = readOptionValue(argv, ++index, token);
    } else if (token.startsWith("--")) {
      throw new AppError(`Unknown argument: ${token}`, 500);
    } else if (!options.configDir) {
      options.configDir = token;
    } else {
      throw new AppError(`Unexpected argument: ${token}`, 500);
    }
  }

  return options;
}

function readOptionValue(
  argv: string[],
  index: number,
  option: string,
): string {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new AppError(`Missing value for argument: ${option}`, 500);
  }
  return value;
}

function parseListenPort(portText: string): number {
  const listenPort = Number.parseInt(portText, 10);
  if (!Number.isInteger(listenPort) || listenPort <= 0 || listenPort > 65535) {
    throw new AppError(`Invalid listen port: ${portText}`, 500);
  }
  return listenPort;
}

function parseCacheTtl(value: string | undefined): number {
  const cacheTtlSeconds = Number.parseInt(
    value ?? `${DEFAULT_TTL_SECONDS}`,
    10,
  );
  if (!Number.isInteger(cacheTtlSeconds) || cacheTtlSeconds < 0) {
    throw new AppError("Invalid --cache-ttl value", 500);
  }
  return cacheTtlSeconds;
}

function splitListen(listen: string): [string, string] {
  const separatorIndex = listen.lastIndexOf(":");
  if (separatorIndex === -1) {
    throw new AppError(`Invalid --listen value: ${listen}`, 500);
  }

  return [listen.slice(0, separatorIndex), listen.slice(separatorIndex + 1)];
}
