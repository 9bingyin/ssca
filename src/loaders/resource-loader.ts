import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AppError } from "../errors";
import { logInfo, logWarn } from "../logger";
import type { FileCacheEntry } from "../types";

const DEFAULT_REMOTE_TIMEOUT_MS = 10_000;
const DEFAULT_REMOTE_RETRY_COUNT = 2;
const DEFAULT_REMOTE_RETRY_DELAY_MS = 200;
const DEFAULT_REMOTE_CACHE_DIR = path.resolve(".cache", "remote-resources");

type RemoteFetch = (url: string, init?: RequestInit) => Promise<Response>;

export interface ResourceLoaderOptions {
  remoteTimeoutMs?: number;
  remoteRetryCount?: number;
  remoteRetryDelayMs?: number;
  remoteFetch?: RemoteFetch;
  remoteCacheDir?: string | false;
}

interface RemoteCacheEntry {
  expiresAt: number;
  value: string;
  etag?: string;
  lastModified?: string;
}

interface RemoteDiskCacheEntry extends RemoteCacheEntry {
  version: 1;
  url: string;
}

interface RemoteFetchResult {
  value: string;
  etag?: string;
  lastModified?: string;
  notModified: boolean;
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
  private readonly remoteCache = new Map<string, RemoteCacheEntry>();
  private readonly remoteTimeoutMs: number;
  private readonly remoteRetryCount: number;
  private readonly remoteRetryDelayMs: number;
  private readonly remoteFetch: RemoteFetch;
  private readonly remoteCacheDir: string | null;

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
    this.remoteCacheDir = resolveRemoteCacheDir(options.remoteCacheDir);
  }

  async loadText(source: string): Promise<string> {
    if (isRemoteSource(source)) {
      return this.loadRemoteText(source);
    }

    if (isFileUrlSource(source)) {
      return this.loadFileText(fileURLToPath(source));
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
    const cached =
      this.remoteCache.get(url) ?? (await this.readRemoteDiskCache(url));
    if (cached) {
      this.remoteCache.set(url, cached);
    }
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const result = await this.fetchRemoteTextWithRetry(url, cached);
    const nextCache: RemoteCacheEntry = {
      expiresAt: Date.now() + this.cacheTtlSeconds * 1000,
      value: result.value,
      etag: result.etag,
      lastModified: result.lastModified,
    };
    this.remoteCache.set(url, nextCache);
    await this.writeRemoteDiskCache(url, nextCache);
    logInfo(
      result.notModified
        ? "Remote resource not modified"
        : "Remote resource refreshed",
      { url },
    );
    return result.value;
  }

  private async fetchRemoteTextWithRetry(
    url: string,
    cached?: RemoteCacheEntry,
  ): Promise<RemoteFetchResult> {
    let lastError: RemoteResourceError | null = null;

    for (let attempt = 0; attempt <= this.remoteRetryCount; attempt += 1) {
      try {
        return await this.fetchRemoteTextOnce(url, cached);
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

  private async fetchRemoteTextOnce(
    url: string,
    cached?: RemoteCacheEntry,
  ): Promise<RemoteFetchResult> {
    const controller = new AbortController();
    const timeout = createTimeout(controller, this.remoteTimeoutMs);

    try {
      const response = await this.remoteFetch(url, {
        headers: getConditionalHeaders(cached),
        signal: timeout ? controller.signal : undefined,
      });
      if (response.status === 304) {
        if (!cached) {
          throw new RemoteResourceError("HTTP 304 Not Modified", false);
        }
        return {
          value: cached.value,
          etag: cached.etag,
          lastModified: cached.lastModified,
          notModified: true,
        };
      }
      if (!response.ok) {
        throw new RemoteResourceError(
          formatHttpError(response),
          response.status === 429 || response.status >= 500,
        );
      }
      return {
        value: await response.text(),
        etag: response.headers.get("etag") ?? undefined,
        lastModified: response.headers.get("last-modified") ?? undefined,
        notModified: false,
      };
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

  private async readRemoteDiskCache(
    url: string,
  ): Promise<RemoteCacheEntry | undefined> {
    if (!this.remoteCacheDir) {
      return undefined;
    }

    const cachePath = this.getRemoteCachePath(url);
    try {
      const raw = await fs.readFile(cachePath, "utf8");
      const parsed = JSON.parse(raw) as unknown;
      if (!isRemoteDiskCacheEntry(parsed, url)) {
        return undefined;
      }
      return {
        expiresAt: parsed.expiresAt,
        value: parsed.value,
        etag: parsed.etag,
        lastModified: parsed.lastModified,
      };
    } catch (error) {
      if (isFileNotFoundError(error)) {
        return undefined;
      }
      logWarn("Remote disk cache read failed", {
        url,
        error: formatFetchError(error),
      });
      return undefined;
    }
  }

  private async writeRemoteDiskCache(
    url: string,
    cache: RemoteCacheEntry,
  ): Promise<void> {
    if (!this.remoteCacheDir) {
      return;
    }

    const cachePath = this.getRemoteCachePath(url);
    const diskCache: RemoteDiskCacheEntry = {
      version: 1,
      url,
      ...cache,
    };

    try {
      await fs.mkdir(this.remoteCacheDir, { recursive: true });
      await fs.writeFile(cachePath, `${JSON.stringify(diskCache)}\n`, "utf8");
    } catch (error) {
      logWarn("Remote disk cache write failed", {
        url,
        error: formatFetchError(error),
      });
    }
  }

  private getRemoteCachePath(url: string): string {
    if (!this.remoteCacheDir) {
      throw new Error("Remote cache directory is disabled");
    }
    return path.join(this.remoteCacheDir, `${hashText(url)}.json`);
  }
}

export function isRemoteSource(source: string): boolean {
  return source.startsWith("http://") || source.startsWith("https://");
}

export function isFileUrlSource(source: string): boolean {
  return source.startsWith("file://");
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

function resolveRemoteCacheDir(
  value: string | false | undefined,
): string | null {
  if (value === false) {
    return null;
  }
  return path.resolve(value ?? DEFAULT_REMOTE_CACHE_DIR);
}

function getConditionalHeaders(
  cached?: RemoteCacheEntry,
): Record<string, string> | undefined {
  const headers: Record<string, string> = {};
  if (cached?.etag) {
    headers["if-none-match"] = cached.etag;
  }
  if (cached?.lastModified) {
    headers["if-modified-since"] = cached.lastModified;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
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

function isFileNotFoundError(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function isRemoteDiskCacheEntry(
  value: unknown,
  url: string,
): value is RemoteDiskCacheEntry {
  if (!value || typeof value !== "object") {
    return false;
  }

  const entry = value as Partial<RemoteDiskCacheEntry>;
  return (
    entry.version === 1 &&
    entry.url === url &&
    typeof entry.expiresAt === "number" &&
    Number.isFinite(entry.expiresAt) &&
    typeof entry.value === "string" &&
    isOptionalString(entry.etag) &&
    isOptionalString(entry.lastModified)
  );
}

function isOptionalString(value: unknown): value is string | undefined {
  return typeof value === "string" || value === undefined;
}

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function delay(milliseconds: number): Promise<void> {
  if (milliseconds <= 0) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
