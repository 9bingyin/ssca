import { AppError } from "../../../errors";
import { normalizeVmessSecurity } from "../../base64/vmess-security";
import {
  applyDialerOptions,
  applyPacketEncoding,
  applyTls,
} from "../outbound-options";
import { applyV2RayTransport } from "../transport";
import {
  getOptionalNumber,
  getOptionalString,
  getPort,
  getString,
  pruneEmpty,
} from "../utils";
import type { JsonRecord } from "../types";

export function convertVmess(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "vmess",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    security: normalizeVmessSecurity(getOptionalString(proxy, "cipher")),
    alter_id: getOptionalNumber(proxy, "alterId") ?? 0,
    tls: {
      enabled: false,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyPacketEncoding(proxy, outbound);
  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}

export function convertVless(proxy: JsonRecord): JsonRecord {
  const encryption = getOptionalString(proxy, "encryption");
  if (encryption && encryption !== "none") {
    throw new AppError("VLESS encryption is not supported by sing-box", 500);
  }

  const flow = getOptionalString(proxy, "flow");
  if (flow && flow !== "xtls-rprx-vision") {
    throw new AppError(`sing-box does not support vless flow: ${flow}`, 500);
  }

  const outbound: JsonRecord = {
    type: "vless",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    flow,
    tls: {
      enabled: false,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyPacketEncoding(proxy, outbound);
  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}

export function convertTrojan(proxy: JsonRecord): JsonRecord {
  if (getOptionalString(proxy, "flow")) {
    throw new AppError("sing-box does not support trojan flow", 500);
  }

  const outbound: JsonRecord = {
    type: "trojan",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  applyV2RayTransport(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, false);
  return pruneEmpty(outbound);
}
