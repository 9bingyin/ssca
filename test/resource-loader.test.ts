import { describe, expect, test } from "bun:test";
import { ResourceLoader } from "../src/loaders/resource-loader";

describe("ResourceLoader remote loading", () => {
  test("retries retryable remote responses", async () => {
    let calls = 0;
    const loader = new ResourceLoader(300, {
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
});
