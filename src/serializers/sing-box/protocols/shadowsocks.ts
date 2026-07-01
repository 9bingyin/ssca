import { AppError } from "../../../errors";
import { applyDialerOptions, applyUdpOverTcp } from "../outbound-options";
import {
  getBoolean,
  getOptionalNumber,
  getOptionalString,
  getPort,
  getRecord,
  getString,
  pruneEmpty,
} from "../utils";
import type { JsonRecord } from "../types";

export function convertShadowsocks(proxy: JsonRecord): JsonRecord {
  const outbound: JsonRecord = {
    type: "shadowsocks",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    method: getString(proxy, "cipher"),
    password: getString(proxy, "password"),
  };

  applyDialerOptions(proxy, outbound);
  applyUdpOverTcp(proxy, outbound);
  applyShadowsocksPlugin(proxy, outbound);
  return pruneEmpty(outbound);
}

export function convertSocks(proxy: JsonRecord): JsonRecord {
  if (getBoolean(proxy, "tls")) {
    throw new AppError("sing-box does not support socks5 with tls", 500);
  }

  const outbound: JsonRecord = {
    type: "socks",
    tag: getString(proxy, "name"),
    server: getString(proxy, "server"),
    server_port: getPort(proxy),
    version: "5",
    username: getOptionalString(proxy, "username"),
    password: getOptionalString(proxy, "password"),
  };

  applyDialerOptions(proxy, outbound);
  applyUdpOverTcp(proxy, outbound);
  return pruneEmpty(outbound);
}

function applyShadowsocksPlugin(proxy: JsonRecord, outbound: JsonRecord): void {
  const plugin = getOptionalString(proxy, "plugin");
  if (!plugin) {
    return;
  }

  const pluginOpts = getRecord(proxy["plugin-opts"]) ?? {};
  const parts: string[] = [];

  if (plugin === "obfs") {
    outbound.plugin = "obfs-local";
    parts.push(`obfs=${getString(pluginOpts, "mode")}`);
    const host = getOptionalString(pluginOpts, "host");
    if (host) parts.push(`obfs-host=${host}`);
  } else if (plugin === "v2ray-plugin") {
    outbound.plugin = "v2ray-plugin";
    const mode = getOptionalString(pluginOpts, "mode");
    if (mode) parts.push(`mode=${mode}`);
    const host = getOptionalString(pluginOpts, "host");
    if (host) parts.push(`host=${host}`);
    const path = getOptionalString(pluginOpts, "path");
    if (path) parts.push(`path=${path}`);
    if (getBoolean(pluginOpts, "tls")) parts.push("tls");
    const sni = getOptionalString(pluginOpts, "sni");
    if (sni) parts.push(`sni=${sni}`);
    if (getBoolean(pluginOpts, "skip-cert-verify")) {
      parts.push("skip-cert-verify=true");
    }
    const mux = getOptionalNumber(pluginOpts, "mux");
    if (typeof mux === "number") parts.push(`mux=${mux}`);
  } else {
    throw new AppError(
      `Unsupported shadowsocks plugin for sing-box target: ${plugin}`,
      500,
    );
  }

  outbound.plugin_opts = parts.join(";");
}
