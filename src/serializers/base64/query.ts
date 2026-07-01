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
  }

  if (!includeV2RayTransport) {
    return query;
  }

  query.set("type", network);

  const wsOpts = getOptionalObject(proxy, "ws-opts");
  const grpcOpts = getOptionalObject(proxy, "grpc-opts");
  const h2Opts = getOptionalObject(proxy, "h2-opts");
  const httpOpts = getOptionalObject(proxy, "http-opts");
  const xhttpOpts = getOptionalObject(proxy, "xhttp-opts");

  if (network === "tcp") {
    query.set("headerType", "none");
  } else if (network === "ws") {
    const host = getHeaderHost(wsOpts);
    if (host) {
      query.set("host", host);
    }
    query.set("path", getOptionalString(wsOpts, "path") ?? "/");
  } else if (network === "grpc") {
    const authority =
      getOptionalString(grpcOpts, "authority") ??
      getOptionalString(proxy, "servername");
    if (authority) {
      query.set("authority", authority);
    }

    const serviceName = getOptionalString(grpcOpts, "grpc-service-name");
    if (serviceName) {
      query.set("serviceName", serviceName);
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
