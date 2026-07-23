import app from "./app";
import { logger } from "./lib/logger";

const rawPort = process.env["PORT"] ?? "3000";
const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

const server = app.listen(port, () => {
  logger.info({ port }, "Server listening");
});

// Express 5: erros de bind (EADDRINUSE, EACCES) só chegam pelo evento 'error'.
server.on("error", (err) => {
  logger.error({ err }, "Server failed to start");
  process.exit(1);
});

// Encerramento gracioso — Render envia SIGTERM em deploys.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    logger.info({ signal }, "Shutting down");
    server.close(() => process.exit(0));
  });
}
