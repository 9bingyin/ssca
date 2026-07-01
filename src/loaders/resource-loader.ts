import fs from "node:fs/promises";
import path from "node:path";
import { AppError } from "../errors";
import { logInfo, logWarn } from "../logger";
import type { CacheEntry, FileCacheEntry } from "../types";

const DEFAULT_REMOTE_TIMEOUT_MS = 10_000;
const DEFAULT_REMOTE_RETRY_COUNT = 2;
const DEFAULT_REMOTE_RETRY_DELAY_MS = 200;

type RemoteFetch = (url: string, init?: RequestInit) => Promise<Response>;

export interface ResourceLoaderOptions {
  remoteTimeoutMs?: number;
  remoteRetryCount?: number;
  remoteRetryDelayMs?: number;
  remoteFetch?: RemoteFetch;
}

class RemoteResourceError extends Error {
  constructor(
    message: string,
    public readonly retryable: boolean,
  ) {
    super(message);
    this.name = "RemoteResourceError";
  }
}

export class ResourceLoader {
  private readonly fileCache = new Map<string, FileCacheEntry<string>>();
  private readonly remoteCache = new Map<string, CacheEntry<string>>();
  private readonly remoteTimeoutMs: number;
  private readonly remoteRetryCount: number;
  private readonly remoteRetryDelayMs: number;
  private readonly remoteFetch: RemoteFetch;

  constructor(
    private readonly cacheTtlSeconds: number,
    options: ResourceLoaderOptions = {},
  ) {
    this.remoteTimeoutMs = resolveNonNegativeOption(
      options.remoteTimeoutMs,
      DEFAULT_REMOTE_TIMEOUT_MS,
    );
    this.remoteRetryCount = Math.trunc(
      resolveNonNegativeOption(
        options.remoteRetryCount,
        DEFAULT_REMOTE_RETRY_COUNT,
      ),
    );
    this.remoteRetryDelayMs = resolveNonNegativeOption(
      options.remoteRetryDelayMs,
      DEFAULT_REMOTE_RETRY_DELAY_MS,
    );
    this.remoteFetch = options.remoteFetch ?? fetch;
  }

  async loadText(source: string): Promise<string> {
    if (isRemoteSource(source)) {
      return this.loadRemoteText(source);
    }

    return this.loadFileText(path.resolve(source));
  }

  private async loadFileText(filePath: string): Promise<string> {
    const stat = await fs.stat(filePath).catch(() => {
      throw new AppError(`File not found: ${filePath}`, 500);
    });

    const cached = this.fileCache.get(filePath);
    if (cached && cached.mtimeMs === stat.mtimeMs) {
      return cached.value;
    }

    const value = await fs.readFile(filePath, "utf8");
    this.fileCache.set(filePath, {
      mtimeMs: stat.mtimeMs,
      value,
    });
    return value;
  }

  private async loadRemoteText(url: string): Promise<string> {
    const now = Date.now();
    const cached = this.remoteCache.get(url);
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const value = await this.fetchRemoteTextWithRetry(url);
    this.remoteCache.set(url, {
      expiresAt: now + this.cacheTtlSeconds * 1000,
      value,
    });
    logInfo("Remote resource refreshed", { url });
    return value;
  }

  private async fetchRemoteTextWithRetry(url: string): Promise<string> {
    let lastError: RemoteResourceError | null = null;

    for (let attempt = 0; attempt <= this.remoteRetryCount; attempt += 1) {
      try {
        return await this.fetchRemoteTextOnce(url);
      } catch (error) {
        const remoteError = normalizeRemoteError(error);
        lastError = remoteError;
        const attemptNumber = attempt + 1;
        const canRetry =
          remoteError.retryable && attempt < this.remoteRetryCount;

        if (!canRetry) {
          throw new AppError(
            `Failed to fetch remote resource: ${url} (${remoteError.message}, attempts: ${attemptNumber})`,
            500,
          );
        }

        logWarn("Remote resource fetch failed, retrying", {
          url,
          attempt: attemptNumber,
          error: remoteError.message,
        });
        await delay(this.remoteRetryDelayMs);
      }
    }

    throw new AppError(
      `Failed to fetch remote resource: ${url} (${lastError?.message ?? "unknown error"})`,
      500,
    );
  }

  private async fetchRemoteTextOnce(url: string): Promise<string> {
    const controller = new AbortController();
    const timeout = createTimeout(controller, this.remoteTimeoutMs);

    try {
      const response = await this.remoteFetch(url, {
        signal: timeout ? controller.signal : undefined,
      });
      if (!response.ok) {
        throw new RemoteResourceError(
          formatHttpError(response),
          response.status === 429 || response.status >= 500,
        );
      }
      return await response.text();
    } catch (error) {
      if (error instanceof RemoteResourceError) {
        throw error;
      }
      if (isAbortError(error)) {
        throw new RemoteResourceError(
          `timed out after ${this.remoteTimeoutMs}ms`,
          true,
        );
      }
      throw new RemoteResourceError(formatFetchError(error), true);
    } finally {
      if (timeout) {
        clearTimeout(timeout);
      }
    }
  }
}

export function isRemoteSource(source: string): boolean {
  return source.startsWith("http://") || source.startsWith("https://");
}

function resolveNonNegativeOption(
  value: number | undefined,
  fallback: number,
): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return fallback;
  }

  return value;
}

function createTimeout(
  controller: AbortController,
  timeoutMs: number,
): ReturnType<typeof setTimeout> | null {
  if (timeoutMs <= 0) {
    return null;
  }

  return setTimeout(() => {
    controller.abort();
  }, timeoutMs);
}

function normalizeRemoteError(error: unknown): RemoteResourceError {
  if (error instanceof RemoteResourceError) {
    return error;
  }
  return new RemoteResourceError(formatFetchError(error), true);
}

function formatHttpError(response: Response): string {
  const statusText = response.statusText ? ` ${response.statusText}` : "";
  return `HTTP ${response.status}${statusText}`;
}

function formatFetchError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return "unknown error";
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function delay(milliseconds: number): Promise<void> {
  if (milliseconds <= 0) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
