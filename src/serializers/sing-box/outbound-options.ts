import {
  getBoolean,
  getOptionalNumber,
  getOptionalString,
  getRecord,
  normalizeFingerprint,
  pruneEmpty,
  toStringArray,
} from "./utils";
import type { JsonRecord } from "./types";

export function applyTls(
  proxy: JsonRecord,
  outbound: JsonRecord,
  forceEnabled: boolean,
): void {
  const tls = getRecord(outbound.tls) ?? { enabled: false };
  if (forceEnabled || getBoolean(proxy, "tls")) {
    tls.enabled = true;
  }

  const serverName =
    getOptionalString(proxy, "servername") ??
    getOptionalString(proxy, "sni") ??
    getOptionalString(proxy, "peer");
  if (serverName) {
    tls.server_name = serverName;
  }
  if (getBoolean(proxy, "skip-cert-verify") || getBoolean(proxy, "insecure")) {
    tls.insecure = true;
  }

  const alpn = toStringArray(proxy.alpn);
  if (alpn.length > 0) {
    tls.alpn = alpn;
  }

  const realityOpts = getRecord(proxy["reality-opts"]);
  if (realityOpts) {
    tls.enabled = true;
    tls.reality = pruneEmpty({
      enabled: true,
      public_key: getOptionalString(realityOpts, "public-key"),
      short_id: getOptionalString(realityOpts, "short-id"),
    });
    tls.utls = { enabled: true };
  }

  const fingerprint = normalizeFingerprint(
    getOptionalString(proxy, "client-fingerprint"),
  );
  if (
    fingerprint &&
    !["hysteria", "hysteria2", "tuic"].includes(`${proxy.type}`)
  ) {
    tls.utls = { ...(getRecord(tls.utls) ?? {}), enabled: true, fingerprint };
  }

  if (tls.enabled) {
    outbound.tls = pruneEmpty(tls);
  } else {
    delete outbound.tls;
  }
}

export function applyPacketEncoding(
  proxy: JsonRecord,
  outbound: JsonRecord,
): void {
  let value = getOptionalString(proxy, "packet-encoding");
  if (!value && getBoolean(proxy, "xudp")) value = "xudp";
  if (!value && getBoolean(proxy, "packet-addr")) value = "packetaddr";
  if (!value) return;

  if (value === "packet") value = "packetaddr";
  if (!["packetaddr", "xudp"].includes(value)) return;
  outbound.packet_encoding = value;
}

export function applyDialerOptions(
  proxy: JsonRecord,
  outbound: JsonRecord,
): void {
  if (getBoolean(proxy, "tfo") || getBoolean(proxy, "tcp-fast-open")) {
    outbound.tcp_fast_open = true;
  }
  const detour =
    getOptionalString(proxy, "dialer-proxy") ??
    getOptionalString(proxy, "detour");
  if (detour) outbound.detour = detour;
}

export function applyUdpOverTcp(proxy: JsonRecord, outbound: JsonRecord): void {
  if (getBoolean(proxy, "uot")) {
    outbound.udp_over_tcp = { enabled: true };
  }
  if (getBoolean(proxy, "udp-over-tcp")) {
    outbound.udp_over_tcp = {
      enabled: true,
      version: getOptionalNumber(proxy, "udp-over-tcp-version") === 2 ? 2 : 1,
    };
  }
}
