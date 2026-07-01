import { AppError } from "../../errors";
import {
  convertAnyTLS,
  convertHysteria2,
  convertTuic,
} from "./protocols/modern";
import { convertShadowsocks, convertSocks } from "./protocols/shadowsocks";
import { convertTrojan, convertVless, convertVmess } from "./protocols/v2ray";
import { convertWireGuard } from "./protocols/wireguard";
import { getString } from "./utils";
import type { JsonRecord } from "./types";

export function convertProxyOutbound(proxy: JsonRecord): JsonRecord {
  const type = getString(proxy, "type");

  switch (type) {
    case "ss":
      return convertShadowsocks(proxy);
    case "socks5":
      return convertSocks(proxy);
    case "vmess":
      return convertVmess(proxy);
    case "vless":
      return convertVless(proxy);
    case "trojan":
      return convertTrojan(proxy);
    case "hysteria2":
      return convertHysteria2(proxy);
    case "tuic":
      return convertTuic(proxy);
    case "wireguard":
      return convertWireGuard(proxy);
    case "anytls":
      return convertAnyTLS(proxy);
    default:
      throw new AppError(
        `Unsupported proxy type for sing-box target: ${type}`,
        500,
      );
  }
}
