import {
  createServer as createHttpServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { AppError } from "./errors";
import { logError, logInfo } from "./logger";
import type { AppConfig } from "./types";
import { ConfigBuilder } from "./services/config-builder";

const MIHOMO_UA_KEYWORDS = [
  "clash",
  "clash-verge",
  "clashforandroid",
  "clashforwindows",
  "clashx",
  "mihomo",
  "metacubex",
];

const BASE64_UA_KEYWORDS = ["v2rayn"];
const SING_BOX_UA_KEYWORDS = ["sing-box", "sfa", "sfi", "sfm"];
type OutputTarget = "mihomo" | "base64" | "sing-box";

export function createServer(
  appConfig: AppConfig,
  builder: ConfigBuilder,
): Server {
  const server = createHttpServer((request, response) => {
    void handleRequest(appConfig, builder, request, response);
  });

  server.listen(appConfig.listenPort, appConfig.listenHost);
  return server;
}

async function handleRequest(
  appConfig: AppConfig,
  builder: ConfigBuilder,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const startedAt = Date.now();
  const url = getRequestUrl(appConfig, request);

  try {
    if (request.method !== "GET") {
      sendTextResponse(response, "Method Not Allowed", 405);
      return;
    }

    if (!isSubscriptionPath(url.pathname, appConfig.subscriptionPath)) {
      sendTextResponse(response, "Not Found", 404);
      return;
    }

    const target = resolveTarget(
      url.searchParams.get("target") ?? "auto",
      getHeader(request.headers, "user-agent"),
    );
    const includeProxyGroupIcons = shouldIncludeProxyGroupIcons(
      target,
      url.searchParams,
    );
    const body = await buildTargetBody(target, builder, {
      includeProxyGroupIcons,
    });
    logInfo("Request served", {
      path: url.pathname,
      target,
      durationMs: Date.now() - startedAt,
    });

    sendResponse(response, body, 200, {
      "content-type": getContentType(target),
      "cache-control": "no-store",
    });
  } catch (error) {
    const appError = normalizeError(error);
    logError("Request failed", {
      path: url.pathname,
      statusCode: appError.statusCode,
      error: appError.message,
      durationMs: Date.now() - startedAt,
    });
    sendTextResponse(response, appError.message, appError.statusCode);
  }
}

export function resolveTarget(
  target: string,
  userAgent: string | null,
): "mihomo" | "base64" | "sing-box" {
  if (target === "mihomo" || target === "base64" || target === "sing-box") {
    return target;
  }
  if (target !== "auto") {
    throw new AppError(`Invalid target: ${target}`, 400);
  }

  const normalized = userAgent?.toLowerCase() ?? "";
  if (!normalized) {
    return "mihomo";
  }

  for (const keyword of BASE64_UA_KEYWORDS) {
    if (normalized.includes(keyword)) {
      return "base64";
    }
  }

  for (const keyword of SING_BOX_UA_KEYWORDS) {
    if (normalized.includes(keyword)) {
      return "sing-box";
    }
  }

  for (const keyword of MIHOMO_UA_KEYWORDS) {
    if (normalized.includes(keyword)) {
      return "mihomo";
    }
  }

  return "mihomo";
}

export function shouldIncludeProxyGroupIcons(
  target: OutputTarget,
  searchParams: URLSearchParams,
): boolean {
  if (target !== "mihomo") {
    return false;
  }

  return isEnabledFlag(
    searchParams.get("icons") ?? searchParams.get("icon") ?? "false",
  );
}

export function isSubscriptionPath(
  pathname: string,
  subscriptionPath = "/",
): boolean {
  return pathname === subscriptionPath;
}

function getRequestUrl(appConfig: AppConfig, request: IncomingMessage): URL {
  const host = getHeader(request.headers, "host");
  const base = `http://${host ?? `${appConfig.listenHost}:${appConfig.listenPort}`}`;
  return new URL(request.url ?? "/", base);
}

function getHeader(headers: IncomingHttpHeaders, name: string): string | null {
  const value = headers[name];
  if (!value) {
    return null;
  }
  return Array.isArray(value) ? value[0] : value;
}

function buildTargetBody(
  target: OutputTarget,
  builder: ConfigBuilder,
  options: { includeProxyGroupIcons: boolean },
): Promise<string> {
  if (target === "base64") {
    return builder.buildBase64Subscription();
  }
  if (target === "sing-box") {
    return builder.buildSingBoxConfig();
  }
  return builder.build({
    includeProxyGroupIcons: options.includeProxyGroupIcons,
  });
}

function getContentType(target: OutputTarget): string {
  if (target === "base64") {
    return "text/plain; charset=utf-8";
  }
  if (target === "sing-box") {
    return "application/json; charset=utf-8";
  }
  return "text/yaml; charset=utf-8";
}

function isEnabledFlag(value: string): boolean {
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function normalizeError(error: unknown): AppError {
  if (error instanceof AppError) {
    return error;
  }

  if (error instanceof Error) {
    return new AppError(error.message, 500);
  }

  return new AppError("Unknown error", 500);
}

function sendTextResponse(
  response: ServerResponse,
  message: string,
  status: number,
): void {
  sendResponse(response, message, status, {
    "content-type": "text/plain; charset=utf-8",
  });
}

function sendResponse(
  response: ServerResponse,
  body: string,
  status: number,
  headers: Record<string, string>,
): void {
  response.writeHead(status, headers);
  response.end(body);
}
