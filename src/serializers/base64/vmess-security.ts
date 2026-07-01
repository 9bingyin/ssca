const VMESS_SECURITY_ALIASES: Record<string, string> = {
  "chacha20-ietf-poly1305": "chacha20-poly1305",
};

const VMESS_SECURITY_VALUES = new Set([
  "auto",
  "none",
  "zero",
  "aes-128-gcm",
  "chacha20-poly1305",
]);

export function normalizeVmessSecurity(value: string | null): string {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return "auto";
  }

  const canonical = VMESS_SECURITY_ALIASES[normalized] ?? normalized;
  return VMESS_SECURITY_VALUES.has(canonical) ? canonical : "auto";
}
