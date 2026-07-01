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

export function createServer(
  appConfig: AppConfig,
  builder: ConfigBuilder,
): Bun.Server<undefined> {
  return Bun.serve({
    hostname: appConfig.listenHost,
    port: appConfig.listenPort,
    async fetch(request) {
      const startedAt = Date.now();
      const url = new URL(request.url);

      try {
        if (request.method !== "GET") {
          return textResponse("Method Not Allowed", 405);
        }

        if (url.pathname !== "/pull") {
          return textResponse("Not Found", 404);
        }

        const target = resolveTarget(
          url.searchParams.get("target") ?? "auto",
          request.headers.get("user-agent"),
        );
        const body = await buildTargetBody(target, builder);
        logInfo("Request served", {
          path: url.pathname,
          target,
          durationMs: Date.now() - startedAt,
        });

        return new Response(body, {
          status: 200,
          headers: {
            "content-type": getContentType(target),
            "cache-control": "no-store",
          },
        });
      } catch (error) {
        const appError = normalizeError(error);
        logError("Request failed", {
          path: url.pathname,
          statusCode: appError.statusCode,
          error: appError.message,
          durationMs: Date.now() - startedAt,
        });
        return textResponse(appError.message, appError.statusCode);
      }
    },
  });
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

function buildTargetBody(
  target: "mihomo" | "base64" | "sing-box",
  builder: ConfigBuilder,
): Promise<string> {
  if (target === "base64") {
    return builder.buildBase64Subscription();
  }
  if (target === "sing-box") {
    return builder.buildSingBoxConfig();
  }
  return builder.build();
}

function getContentType(target: "mihomo" | "base64" | "sing-box"): string {
  if (target === "base64") {
    return "text/plain; charset=utf-8";
  }
  if (target === "sing-box") {
    return "application/json; charset=utf-8";
  }
  return "text/yaml; charset=utf-8";
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

function textResponse(message: string, status: number): Response {
  return new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
    },
  });
}
