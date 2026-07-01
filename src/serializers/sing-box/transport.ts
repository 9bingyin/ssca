import { AppError } from "../../errors";
import {
  applyNumber,
  firstString,
  getBoolean,
  getOptionalString,
  getRecord,
  pruneEmpty,
  stringifyHeaderValue,
  toStringArray,
} from "./utils";
import type { JsonRecord } from "./types";

export function applyV2RayTransport(
  proxy: JsonRecord,
  outbound: JsonRecord,
): void {
  const network = getOptionalString(proxy, "network") ?? "tcp";
  if (network === "tcp") {
    return;
  }
  if (network === "xhttp") {
    throw new AppError("sing-box does not support xhttp transport", 500);
  }

  switch (network) {
    case "ws":
      outbound.transport = buildWebSocketTransport(proxy);
      break;
    case "grpc":
      outbound.transport = buildGrpcTransport(proxy);
      break;
    case "h2":
    case "http":
      outbound.transport = buildHttpTransport(proxy, network);
      break;
    default:
      throw new AppError(
        `Unsupported network for sing-box target: ${network}`,
        500,
      );
  }
}

function buildWebSocketTransport(proxy: JsonRecord): JsonRecord {
  const wsOpts = getRecord(proxy["ws-opts"]) ?? {};
  const headers = getRecord(wsOpts.headers) ?? {};
  const isHttpUpgrade = getBoolean(wsOpts, "v2ray-http-upgrade");
  const host = stringifyHeaderValue(headers, "Host");
  const transport: JsonRecord = {
    type: isHttpUpgrade ? "httpupgrade" : "ws",
    path: getOptionalString(wsOpts, "path"),
  };

  if (isHttpUpgrade) {
    if (host) transport.host = host;
    const remainingHeaders = { ...headers };
    delete remainingHeaders.Host;
    if (Object.keys(remainingHeaders).length > 0) {
      transport.headers = remainingHeaders;
    }
  } else {
    if (Object.keys(headers).length > 0) transport.headers = headers;
    applyNumber(wsOpts, transport, "max-early-data", "max_early_data");
    const earlyDataHeader = getOptionalString(wsOpts, "early-data-header-name");
    if (earlyDataHeader) transport.early_data_header_name = earlyDataHeader;
  }

  return pruneEmpty(transport);
}

function buildGrpcTransport(proxy: JsonRecord): JsonRecord {
  const grpcOpts = getRecord(proxy["grpc-opts"]) ?? {};
  return pruneEmpty({
    type: "grpc",
    service_name: getOptionalString(grpcOpts, "grpc-service-name"),
  });
}

function buildHttpTransport(proxy: JsonRecord, network: string): JsonRecord {
  const opts =
    getRecord(proxy[network === "h2" ? "h2-opts" : "http-opts"]) ?? {};
  const headers = getRecord(opts.headers) ?? {};
  const host = network === "h2" ? opts.host : headers.Host;
  const transport: JsonRecord = {
    type: "http",
    host: toStringArray(host),
    path: firstString(opts.path),
  };

  const method = getOptionalString(opts, "method");
  if (method) transport.method = method;
  return pruneEmpty(transport);
}
