import {
  booleanToBinary,
  getBoolean,
  getHeaderHost,
  getName,
  getOptionalObject,
  getOptionalString,
  getOptionalUnknown,
  getString,
  normalizeNetwork,
  stringifyAlpn,
  stringifyHeaderValue,
  stringifyHostList,
  stringifyPathList,
  type ProxyRecord,
} from "./helpers";

const DEFAULT_WS_EARLY_DATA_HEADER = "Sec-WebSocket-Protocol";

export function buildUriQuery(
  proxy: ProxyRecord,
  includeV2RayTransport: boolean,
  securityDefault: string | null,
): URLSearchParams {
  const query = new URLSearchParams();
  const network = normalizeNetwork(getOptionalString(proxy, "network"));
  const tls = getBoolean(proxy, "tls");
  const realityOpts = getOptionalObject(proxy, "reality-opts");
  const servername =
    getOptionalString(proxy, "servername") ?? getOptionalString(proxy, "sni");
  const alpn = stringifyAlpn(getOptionalUnknown(proxy, "alpn"));
  const clientFingerprint = getOptionalString(proxy, "client-fingerprint");
  const skipCertVerify = getBoolean(proxy, "skip-cert-verify");
  const tlsFingerprint = getOptionalString(proxy, "fingerprint");

  if (realityOpts) {
    query.set("security", "reality");
  } else if (tls) {
    query.set("security", "tls");
  } else if (securityDefault !== null) {
    query.set("security", securityDefault);
  }

  if (servername) {
    query.set("sni", servername);
  }
  if (clientFingerprint) {
    query.set("fp", clientFingerprint);
  }
  if (tlsFingerprint) {
    query.set("pcs", tlsFingerprint);
  }

  if (tls && !realityOpts) {
    if (alpn) {
      query.set("alpn", alpn);
    }
    query.set("insecure", booleanToBinary(skipCertVerify));
    query.set("allowInsecure", booleanToBinary(skipCertVerify));
  }

  if (realityOpts) {
    query.set("pbk", getString(realityOpts, "public-key"));
    const shortId = getOptionalString(realityOpts, "short-id");
    if (shortId) {
      query.set("sid", shortId);
    }
    const spiderX = getOptionalString(realityOpts, "_spider-x");
    if (spiderX) {
      query.set("spx", spiderX);
    }
  }

  const packetEncoding = resolvePacketEncoding(proxy);
  if (packetEncoding) {
    query.set("packetEncoding", packetEncoding);
  }

  if (!includeV2RayTransport) {
    return query;
  }

  const wsOpts = getOptionalObject(proxy, "ws-opts");
  const grpcOpts = getOptionalObject(proxy, "grpc-opts");
  const h2Opts = getOptionalObject(proxy, "h2-opts");
  const httpOpts = getOptionalObject(proxy, "http-opts");
  const xhttpOpts = getOptionalObject(proxy, "xhttp-opts");

  query.set("type", resolveTransportType(network, wsOpts));

  if (network === "tcp") {
    query.set("headerType", "none");
  } else if (network === "ws") {
    applyWebSocketTransportQuery(query, wsOpts);
  } else if (network === "grpc") {
    const authority =
      getOptionalString(grpcOpts, "authority") ??
      getOptionalString(grpcOpts, "_grpc-authority") ??
      getOptionalString(proxy, "servername");
    if (authority) {
      query.set("authority", authority);
    }

    const serviceName = getOptionalString(grpcOpts, "grpc-service-name");
    if (serviceName) {
      query.set("serviceName", serviceName);
    }

    const mode = getOptionalString(grpcOpts, "_grpc-type");
    if (mode) {
      query.set("mode", mode);
    }
  } else if (network === "h2") {
    const host = stringifyHostList(h2Opts?.host);
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(h2Opts, "path") ?? "/");
  } else if (network === "http") {
    const host = stringifyHeaderValue(httpOpts?.headers, "Host");
    if (host) {
      query.set("host", host);
    }
    const path = stringifyPathList(httpOpts?.path);
    if (path) {
      query.set("path", path);
    }
    const method = getOptionalString(httpOpts, "method");
    if (method) {
      query.set("method", method);
    }
  } else if (network === "xhttp") {
    const host = getOptionalString(xhttpOpts, "host");
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(xhttpOpts, "path") ?? "/");
    const mode = getOptionalString(xhttpOpts, "mode");
    if (mode) {
      query.set("mode", mode);
    }
  }

  return query;
}

export function resolveVmessType(proxy: ProxyRecord, network: string): string {
  if (network === "grpc") {
    return (
      getOptionalString(getOptionalObject(proxy, "grpc-opts"), "mode") ?? "none"
    );
  }
  if (network === "xhttp") {
    return (
      getOptionalString(getOptionalObject(proxy, "xhttp-opts"), "mode") ??
      "none"
    );
  }
  return getOptionalString(proxy, "headerType") ?? "none";
}

export function applyLiteSecurityQuery(
  proxy: ProxyRecord,
  query: URLSearchParams,
): void {
  const sni =
    getOptionalString(proxy, "sni") ?? getOptionalString(proxy, "servername");
  if (sni) {
    query.set("sni", sni);
  }

  const alpn = stringifyAlpn(getOptionalUnknown(proxy, "alpn"));
  if (alpn) {
    query.set("alpn", alpn);
  }

  if (getBoolean(proxy, "skip-cert-verify")) {
    query.set("insecure", "1");
    query.set("allowInsecure", "1");
  } else {
    query.set("insecure", "0");
    query.set("allowInsecure", "0");
  }
}

export function buildUri(
  scheme: string,
  authority: string,
  query: URLSearchParams,
  proxy: ProxyRecord,
): string {
  const serializedQuery = query.toString();
  const remark = encodeURIComponent(getName(proxy));
  return `${scheme}://${authority}${serializedQuery ? `?${serializedQuery}` : ""}#${remark}`;
}

function resolveTransportType(
  network: string,
  wsOpts: ProxyRecord | null,
): string {
  if (network === "ws" && getBoolean(wsOpts, "v2ray-http-upgrade")) {
    return "httpupgrade";
  }

  return network;
}

function applyWebSocketTransportQuery(
  query: URLSearchParams,
  wsOpts: ProxyRecord | null,
): void {
  const host = getHeaderHost(wsOpts);
  if (host) {
    query.set("host", host);
  }

  const maxEarlyData = getOptionalIntegerText(wsOpts, "max-early-data");
  const earlyDataHeader = getOptionalString(wsOpts, "early-data-header-name");
  const httpUpgradeFastOpen = getBoolean(
    wsOpts,
    "v2ray-http-upgrade-fast-open",
  );
  const path = getOptionalString(wsOpts, "path") ?? "/";

  if (httpUpgradeFastOpen && maxEarlyData) {
    query.set("path", setPathQueryParam(path, "ed", maxEarlyData));
  } else {
    query.set("path", path);
  }

  if (!getBoolean(wsOpts, "v2ray-http-upgrade") && maxEarlyData) {
    query.set("ed", maxEarlyData);
  }

  if (earlyDataHeader && earlyDataHeader !== DEFAULT_WS_EARLY_DATA_HEADER) {
    query.set("eh", earlyDataHeader);
  }
}

function resolvePacketEncoding(proxy: ProxyRecord): string | null {
  if (getOptionalString(proxy, "type") !== "vless") {
    return null;
  }

  const explicit = getOptionalString(proxy, "packet-encoding");
  if (explicit === "packetaddr") {
    return "packet";
  }
  if (explicit === "xudp" || explicit === "none" || explicit === "packet") {
    return explicit;
  }
  if (getBoolean(proxy, "xudp")) {
    return "xudp";
  }
  if (getBoolean(proxy, "packet-addr")) {
    return "packet";
  }
  return null;
}

function getOptionalIntegerText(
  object: ProxyRecord | null | undefined,
  key: string,
): string | null {
  const value = object?.[key];
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return `${value}`;
  }
  if (typeof value === "string" && /^\d+$/u.test(value.trim())) {
    return value.trim();
  }
  return null;
}

function setPathQueryParam(path: string, key: string, value: string): string {
  const [pathname, rawQuery = ""] = path.split("?", 2);
  const params = new URLSearchParams(rawQuery);
  params.set(key, value);
  return `${pathname || "/"}?${params.toString()}`;
}
