import path from "node:path";
import { AppError } from "./errors";
import type { AppConfig } from "./types";

const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_PORT = 3000;
const DEFAULT_TTL_SECONDS = 300;

export function parseCliArgs(argv: string[]): AppConfig {
  const options = new Map<string, string>();

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new AppError(`Unexpected argument: ${token}`, 500);
    }

    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      throw new AppError(`Missing value for argument: ${token}`, 500);
    }

    options.set(token, next);
    index += 1;
  }

  const listen = options.get("--listen") ?? `${DEFAULT_HOST}:${DEFAULT_PORT}`;
  const [listenHost, portText] = splitListen(listen);
  const listenPort = Number.parseInt(portText, 10);
  if (!Number.isInteger(listenPort) || listenPort <= 0 || listenPort > 65535) {
    throw new AppError(`Invalid listen port: ${portText}`, 500);
  }

  const proxiesFile = requirePath(options, "--proxies-file");
  const templateFile = requirePath(options, "--template-file");
  const profileIni = requireValue(options, "--profile-ini");

  const cacheTtlSeconds = Number.parseInt(
    options.get("--cache-ttl") ?? `${DEFAULT_TTL_SECONDS}`,
    10,
  );
  if (!Number.isInteger(cacheTtlSeconds) || cacheTtlSeconds < 0) {
    throw new AppError("Invalid --cache-ttl value", 500);
  }

  return {
    listenHost,
    listenPort,
    proxiesFile: path.resolve(proxiesFile),
    profileIni,
    templateFile: path.resolve(templateFile),
    cacheTtlSeconds,
  };
}

function requirePath(options: Map<string, string>, key: string): string {
  return requireValue(options, key);
}

function requireValue(options: Map<string, string>, key: string): string {
  const value = options.get(key);
  if (!value) {
    throw new AppError(`Missing required argument: ${key}`, 500);
  }
  return value;
}

function splitListen(listen: string): [string, string] {
  const separatorIndex = listen.lastIndexOf(":");
  if (separatorIndex === -1) {
    throw new AppError(`Invalid --listen value: ${listen}`, 500);
  }

  return [listen.slice(0, separatorIndex), listen.slice(separatorIndex + 1)];
}
