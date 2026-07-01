import { AppError } from "../../errors";
import { ENDPOINT_TYPES, OUTBOUND_TYPES } from "./constants";
import { expectArray, expectRecord, expectString } from "./helpers";

export function validateOutboundAndEndpointTags(
  outbounds: unknown[],
  endpoints: unknown[],
): Set<string> {
  const tags = new Set<string>();

  for (const [index, outbound] of outbounds.entries()) {
    const record = expectRecord(outbound, `outbounds[${index}] format invalid`);
    const type = expectString(record.type, `outbounds[${index}]: missing type`);
    if (!OUTBOUND_TYPES.has(type)) {
      throw new AppError(
        `outbounds[${index}]: unknown outbound type: ${type}`,
        500,
      );
    }
    addUniqueTag(tags, getTag(record, index));
  }

  for (const [index, endpoint] of endpoints.entries()) {
    const record = expectRecord(endpoint, `endpoints[${index}] format invalid`);
    const type = expectString(record.type, `endpoints[${index}]: missing type`);
    if (!ENDPOINT_TYPES.has(type)) {
      throw new AppError(
        `endpoints[${index}]: unknown endpoint type: ${type}`,
        500,
      );
    }
    addUniqueTag(tags, getTag(record, index));
  }

  validateOutboundReferences(outbounds, tags);
  return tags;
}

function validateOutboundReferences(
  outbounds: unknown[],
  tags: Set<string>,
): void {
  for (const [index, outbound] of outbounds.entries()) {
    const record = expectRecord(outbound, `outbounds[${index}] format invalid`);
    const type = `${record.type}`;
    if (type !== "selector" && type !== "urltest") {
      continue;
    }

    const members = expectArray(
      record.outbounds,
      `outbounds[${index}]: missing outbounds`,
    );
    if (members.length === 0) {
      throw new AppError(`outbounds[${index}]: missing outbounds`, 500);
    }
    for (const [memberIndex, member] of members.entries()) {
      const tag = expectString(
        member,
        `outbounds[${index}].outbounds[${memberIndex}] format invalid`,
      );
      if (!tags.has(tag)) {
        throw new AppError(
          `outbounds[${index}].outbounds[${memberIndex}]: outbound not found: ${tag}`,
          500,
        );
      }
    }
  }
}

function getTag(record: Record<string, unknown>, index: number): string {
  return typeof record.tag === "string" && record.tag ? record.tag : `${index}`;
}

function addUniqueTag(tags: Set<string>, tag: string): void {
  if (tags.has(tag)) {
    throw new AppError(`duplicate outbound/endpoint tag: ${tag}`, 500);
  }
  tags.add(tag);
}
