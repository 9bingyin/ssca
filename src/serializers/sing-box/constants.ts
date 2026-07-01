import type { JsonRecord } from "./types";

export const BUILTIN_OUTBOUNDS: JsonRecord[] = [
  { type: "direct", tag: "DIRECT" },
  { type: "block", tag: "REJECT" },
  { type: "block", tag: "REJECT-DROP" },
];

export const SING_BOX_UTLS_FINGERPRINTS = new Set([
  "chrome",
  "firefox",
  "edge",
  "safari",
  "360",
  "qq",
  "ios",
  "android",
  "random",
  "randomized",
]);
