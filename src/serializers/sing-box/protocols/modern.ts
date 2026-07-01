import { AppError } from "../../../errors";
import { applyDialerOptions, applyTls } from "../outbound-options";
import {
  applyDurationMilliseconds,
  applyDurationSeconds,
  applyNumber,
  getBoolean,
  getOptionalString,
  getPort,
  getString,
  pruneEmpty,
} from "../utils";
import type { JsonRecord } from "../types";

export function convertHysteria2(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "hysteria2",
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

  const obfs = getOptionalString(proxy, "obfs");
  if (obfs === "salamander" || obfs === "gecko") {
    outbound.obfs = pruneEmpty({
      type: obfs,
      password: getOptionalString(proxy, "obfs-password"),
    });
  }

  applyNumber(proxy, outbound, "up", "up_mbps");
  applyNumber(proxy, outbound, "down", "down_mbps");
  applyDurationSeconds(proxy, outbound, "hop-interval", "hop_interval");
  applyServerPorts(proxy, outbound);
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

export function convertTuic(proxy: JsonRecord): JsonRecord {
  if (getOptionalString(proxy, "token")) {
    throw new AppError("sing-box does not support TUIC v4 token mode", 500);
  }

  const outbound: JsonRecord = {
    type: "tuic",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    uuid: getString(proxy, "uuid"),
    password: getString(proxy, "password"),
    tls: {
      enabled: true,
      server_name: getString(proxy, "server"),
      insecure: false,
    },
  };

  const congestionControl = getOptionalString(proxy, "congestion-controller");
  if (congestionControl && congestionControl !== "cubic") {
    outbound.congestion_control = congestionControl;
  }
  const relayMode = getOptionalString(proxy, "udp-relay-mode");
  if (relayMode && relayMode !== "native") {
    outbound.udp_relay_mode = relayMode;
  }
  if (getBoolean(proxy, "reduce-rtt")) {
    outbound.zero_rtt_handshake = true;
  }
  if (getBoolean(proxy, "udp-over-stream")) {
    outbound.udp_over_stream = true;
  }
  applyDurationMilliseconds(proxy, outbound, "heartbeat-interval", "heartbeat");

  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

export function convertAnyTLS(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "anytls",
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

  applyDurationSeconds(
    proxy,
    outbound,
    "idle-session-check-interval",
    "idle_session_check_interval",
  );
  applyDurationSeconds(
    proxy,
    outbound,
    "idle-session-timeout",
    "idle_session_timeout",
  );
  applyNumber(proxy, outbound, "min-idle-session", "min_idle_session");
  applyDialerOptions(proxy, outbound);
  applyTls(proxy, outbound, true);
  return pruneEmpty(outbound);
}

function applyServerPorts(proxy: JsonRecord, outbound: JsonRecord): void {
  const ports = getOptionalString(proxy, "ports");
  if (!ports) return;
  outbound.server_ports = ports.split(/\s*,\s*/u).map((port) => {
    const range = port.replace(/\s*-\s*/u, ":");
    return range.includes(":") ? range : `${range}:${range}`;
  });
}
