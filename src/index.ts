import { parseCliArgs } from "./cli";
import { createServer } from "./http";
import { logInfo } from "./logger";
import { ResourceLoader } from "./loaders/resource-loader";
import { ConfigBuilder } from "./services/config-builder";

const config = parseCliArgs(Bun.argv.slice(2));
const loader = new ResourceLoader(config.cacheTtlSeconds);
const builder = new ConfigBuilder(config, loader);
const server = createServer(config, builder);

logInfo("Server started", {
  host: config.listenHost,
  port: config.listenPort,
  proxiesFile: config.proxiesFile,
  profileIni: config.profileIni,
  templateFile: config.templateFile,
  cacheTtlSeconds: config.cacheTtlSeconds,
});
