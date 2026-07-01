import { validateBase64SubscriptionProxies } from "../validators";
import { serializeProxy } from "./base64/protocols";

export function serializeBase64Subscription(
  proxies: Record<string, unknown>[],
): string {
  validateBase64SubscriptionProxies(proxies);

  const lines = proxies.map((proxy) => serializeProxy(proxy));
  return Buffer.from(lines.join("\n"), "utf8").toString("base64");
}
