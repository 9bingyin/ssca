import fs from "node:fs/promises";
import path from "node:path";
import { AppError } from "../errors";
import { logInfo } from "../logger";
import type { CacheEntry, FileCacheEntry } from "../types";

export class ResourceLoader {
  private readonly fileCache = new Map<string, FileCacheEntry<string>>();
  private readonly remoteCache = new Map<string, CacheEntry<string>>();

  constructor(private readonly cacheTtlSeconds: number) {}

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
      value
    });
    return value;
  }

  private async loadRemoteText(url: string): Promise<string> {
    const now = Date.now();
    const cached = this.remoteCache.get(url);
    if (cached && cached.expiresAt > now) {
      return cached.value;
    }

    const response = await fetch(url);
    if (!response.ok) {
      throw new AppError(`Failed to fetch remote resource: ${url}`, 500);
    }

    const value = await response.text();
    this.remoteCache.set(url, {
      expiresAt: now + this.cacheTtlSeconds * 1000,
      value
    });
    logInfo("Remote resource refreshed", { url });
    return value;
  }
}

export function isRemoteSource(source: string): boolean {
  return source.startsWith("http://") || source.startsWith("https://");
}
