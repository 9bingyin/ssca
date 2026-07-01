import { AppError } from "../../../errors";
import { applyDialerOptions } from "../outbound-options";
import {
  applyNumber,
  getArray,
  getOptionalNumber,
  getOptionalString,
  getPort,
  getRecord,
  getString,
  pruneEmpty,
  toNumberArray,
} from "../utils";
import type { JsonRecord } from "../types";

export function convertWireGuard(proxy: JsonRecord): JsonRecord {
  const peers = getArray(proxy, "peers");
  const endpoint: JsonRecord = {
    type: "wireguard",
    tag: getString(proxy, "name"),
    address: resolveWireGuardAddress(proxy),
    private_key: getString(proxy, "private-key"),
    peers: (peers.length > 0 ? peers : [{}]).map((peer) =>
      convertWireGuardPeer(getRecord(peer) ?? {}, proxy),
    ),
  };

  applyNumber(proxy, endpoint, "mtu", "mtu");
  applyDialerOptions(proxy, endpoint);
  return pruneEmpty(endpoint);
}

function convertWireGuardPeer(peer: JsonRecord, proxy: JsonRecord): JsonRecord {
  const server =
    getOptionalString(peer, "server") ?? getString(proxy, "server");
  const port = getOptionalNumber(peer, "port") ?? getPort(proxy);
  return pruneEmpty({
    address: server,
    port,
    public_key:
      getOptionalString(peer, "public-key") ??
      getOptionalString(peer, "public_key") ??
      getString(proxy, "public-key"),
    pre_shared_key:
      getOptionalString(peer, "pre-shared-key") ??
      getOptionalString(peer, "pre_shared_key") ??
      getOptionalString(proxy, "pre-shared-key"),
    allowed_ips: getArray(peer, "allowed-ips").length
      ? getArray(peer, "allowed-ips")
      : ["0.0.0.0/0"],
    reserved: toNumberArray(peer.reserved).length
      ? toNumberArray(peer.reserved)
      : toNumberArray(proxy.reserved),
  });
}

function resolveWireGuardAddress(proxy: JsonRecord): string[] {
  const explicit = getArray(proxy, "ip").map((item) => `${item}`);
  if (explicit.length > 0) return explicit;

  const ipv4 = getOptionalString(proxy, "ip");
  const ipv6 = getOptionalString(proxy, "ipv6");
  const addresses: string[] = [];
  if (ipv4) addresses.push(ipv4.includes("/") ? ipv4 : `${ipv4}/32`);
  if (ipv6) addresses.push(ipv6.includes("/") ? ipv6 : `${ipv6}/128`);
  if (addresses.length === 0) {
    throw new AppError(
      `WireGuard proxy ${getString(proxy, "name")} is missing address`,
      500,
    );
  }
  return addresses;
}
