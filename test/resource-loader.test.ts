import { describe, expect, test } from "bun:test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { ResourceLoader } from "../src/loaders/resource-loader";

describe("ResourceLoader remote loading", () => {
  test("retries retryable remote responses", async () => {
    let calls = 0;
    const loader = new ResourceLoader(300, {
      remoteCacheDir: false,
      remoteRetryDelayMs: 0,
      remoteFetch: async () => {
        calls += 1;
        if (calls === 1) {
          return new Response("bad gateway", {
            status: 502,
            statusText: "Bad Gateway",
          });
        }
        return new Response("ok");
      },
    });

    await expect(
      loader.loadText("https://example.com/rules.list"),
    ).resolves.toBe("ok");
    expect(calls).toBe(2);
  });

  test("does not retry non-retryable HTTP responses", async () => {
    let calls = 0;
    const loader = new ResourceLoader(300, {
      remoteCacheDir: false,
      remoteRetryDelayMs: 0,
      remoteFetch: async () => {
        calls += 1;
        return new Response("not found", {
          status: 404,
          statusText: "Not Found",
        });
      },
    });

    await expect(
      loader.loadText("https://example.com/missing.list"),
    ).rejects.toThrow("HTTP 404 Not Found");
    expect(calls).toBe(1);
  });

  test("times out stalled remote requests", async () => {
    const loader = new ResourceLoader(300, {
      remoteCacheDir: false,
      remoteTimeoutMs: 1,
      remoteRetryCount: 0,
      remoteFetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        }),
    });

    await expect(
      loader.loadText("https://example.com/stalled.list"),
    ).rejects.toThrow("timed out after 1ms");
  });

  test("revalidates expired cache with ETag and reuses cached body on 304", async () => {
    const requestHeaders: Array<Record<string, string> | undefined> = [];
    let calls = 0;
    const loader = new ResourceLoader(0, {
      remoteCacheDir: false,
      remoteFetch: async (_url, init) => {
        calls += 1;
        requestHeaders.push(
          init?.headers as Record<string, string> | undefined,
        );
        if (calls === 1) {
          return new Response("version 1", {
            headers: {
              etag: '"v1"',
            },
          });
        }
        return new Response(null, { status: 304 });
      },
    });

    await expect(
      loader.loadText("https://example.com/rules.list"),
    ).resolves.toBe("version 1");
    await expect(
      loader.loadText("https://example.com/rules.list"),
    ).resolves.toBe("version 1");

    expect(calls).toBe(2);
    expect(requestHeaders[0]).toBeUndefined();
    expect(requestHeaders[1]).toEqual({ "if-none-match": '"v1"' });
  });

  test("sends Last-Modified validator and refreshes modified content", async () => {
    const requestHeaders: Array<Record<string, string> | undefined> = [];
    let calls = 0;
    const loader = new ResourceLoader(0, {
      remoteCacheDir: false,
      remoteFetch: async (_url, init) => {
        calls += 1;
        requestHeaders.push(
          init?.headers as Record<string, string> | undefined,
        );
        if (calls === 1) {
          return new Response("version 1", {
            headers: {
              "last-modified": "Wed, 01 Jul 2026 00:00:00 GMT",
            },
          });
        }
        return new Response("version 2", {
          headers: {
            "last-modified": "Wed, 01 Jul 2026 01:00:00 GMT",
          },
        });
      },
    });

    await expect(
      loader.loadText("https://example.com/rules.list"),
    ).resolves.toBe("version 1");
    await expect(
      loader.loadText("https://example.com/rules.list"),
    ).resolves.toBe("version 2");

    expect(calls).toBe(2);
    expect(requestHeaders[1]).toEqual({
      "if-modified-since": "Wed, 01 Jul 2026 00:00:00 GMT",
    });
  });

  test("loads local file URL sources", async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "ssca-file-url-"));
    const filePath = path.join(tempRoot, "profile.ini");

    try {
      await fs.writeFile(filePath, "[custom]\n", "utf8");
      const loader = new ResourceLoader(300, { remoteCacheDir: false });

      await expect(loader.loadText(pathToFileURL(filePath).href)).resolves.toBe(
        "[custom]\n",
      );
    } finally {
      await fs.rm(tempRoot, { force: true, recursive: true });
    }
  });

  test("persists remote cache metadata to disk across loader instances", async () => {
    const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "ssca-cache-"));
    const requestHeaders: Array<Record<string, string> | undefined> = [];
    let calls = 0;

    try {
      const firstLoader = new ResourceLoader(0, {
        remoteCacheDir: tempRoot,
        remoteFetch: async (_url, init) => {
          calls += 1;
          requestHeaders.push(
            init?.headers as Record<string, string> | undefined,
          );
          return new Response("disk version 1", {
            headers: {
              etag: '"disk-v1"',
            },
          });
        },
      });

      await expect(
        firstLoader.loadText("https://example.com/disk-rules.list"),
      ).resolves.toBe("disk version 1");

      const secondLoader = new ResourceLoader(0, {
        remoteCacheDir: tempRoot,
        remoteFetch: async (_url, init) => {
          calls += 1;
          requestHeaders.push(
            init?.headers as Record<string, string> | undefined,
          );
          return new Response(null, { status: 304 });
        },
      });

      await expect(
        secondLoader.loadText("https://example.com/disk-rules.list"),
      ).resolves.toBe("disk version 1");

      expect(calls).toBe(2);
      expect(requestHeaders[0]).toBeUndefined();
      expect(requestHeaders[1]).toEqual({ "if-none-match": '"disk-v1"' });
      expect(await fs.readdir(tempRoot)).toHaveLength(1);
    } finally {
      await fs.rm(tempRoot, { force: true, recursive: true });
    }
  });
});
