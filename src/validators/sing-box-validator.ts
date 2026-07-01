import { TOP_LEVEL_FIELDS } from "./sing-box/constants";
import { expectOptionalArray, validateKnownFields } from "./sing-box/helpers";
import { validateOutboundAndEndpointTags } from "./sing-box/outbounds";
import { validateRoute } from "./sing-box/route";

export function validateSingBoxConfig(config: Record<string, unknown>): void {
  validateKnownFields(config, TOP_LEVEL_FIELDS, "sing-box config");
  const endpoints = expectOptionalArray(config.endpoints, "endpoints");
  const outbounds = expectOptionalArray(config.outbounds, "outbounds");
  const tags = validateOutboundAndEndpointTags(outbounds, endpoints);
  validateRoute(config.route, tags);
}
