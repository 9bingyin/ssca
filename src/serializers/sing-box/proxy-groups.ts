import { AppError } from "../../errors";
import {
  formatDurationSeconds,
  getArray,
  getOptionalNumber,
  getOptionalString,
  getString,
  pruneEmpty,
} from "./utils";
import type { JsonRecord } from "./types";

export function convertProxyGroupOutbound(group: JsonRecord): JsonRecord {
  const type = getString(group, "type");
  const outbounds = getArray(group, "proxies").map((item) => `${item}`);

  if (type === "select") {
    return {
      type: "selector",
      tag: getString(group, "name"),
      outbounds,
    };
  }

  if (type === "url-test" || type === "fallback" || type === "load-balance") {
    return pruneEmpty({
      type: "urltest",
      tag: getString(group, "name"),
      outbounds,
      url: getOptionalString(group, "url"),
      interval: formatDurationSeconds(getOptionalNumber(group, "interval")),
      tolerance: getOptionalNumber(group, "tolerance"),
    });
  }

  throw new AppError(
    `Unsupported proxy group type for sing-box target: ${type}`,
    500,
  );
}
