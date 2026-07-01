import { parseCliArgs } from "./cli";
import { createServer } from "./http";
import { logInfo } from "./logger";
import { ResourceLoader } from "./loaders/resource-loader";
import { ConfigBuilder } from "./services/config-builder";

const config = parseCliArgs(process.argv.slice(2));
const loader = new ResourceLoader(config.cacheTtlSeconds);
const builder = new ConfigBuilder(config, loader);
createServer(config, builder);

logInfo("Server started", {
  host: config.listenHost,
  port: config.listenPort,
  configDir: config.configDir,
  subscriptionPath: config.subscriptionPath,
  cacheTtlSeconds: config.cacheTtlSeconds,
});
