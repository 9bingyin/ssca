export function logInfo(message: string, data?: Record<string, unknown>): void {
  log("INFO", message, data);
}

export function logWarn(message: string, data?: Record<string, unknown>): void {
  log("WARN", message, data);
}

export function logError(
  message: string,
  data?: Record<string, unknown>,
): void {
  log("ERROR", message, data);
}

function log(
  level: string,
  message: string,
  data?: Record<string, unknown>,
): void {
  const payload = {
    level,
    message,
    ...(data ? { data } : {}),
  };
  console.log(JSON.stringify(payload));
}
