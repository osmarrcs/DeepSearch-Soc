import { Router, type IRouter } from "express";
import { pool } from "@workspace/db";
import { HealthCheckResponse } from "@workspace/api-zod";

const router: IRouter = Router();

// Liveness: confirma somente que o processo Express está ativo.
router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

// Readiness do banco: confirma DNS, TLS, autenticação e consulta SQL.
router.get("/healthz/db", async (_req, res): Promise<void> => {
  const inicio = Date.now();

  try {
    const resultado = await pool.query(
      "select current_database() as database, current_user as user, now() as server_time",
    );

    res.json({
      status: "ok",
      database: resultado.rows[0]?.database ?? null,
      user: resultado.rows[0]?.user ?? null,
      serverTime: resultado.rows[0]?.server_time ?? null,
      latencyMs: Date.now() - inicio,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Database error";

    res.status(503).json({
      status: "error",
      error: message,
      latencyMs: Date.now() - inicio,
    });
  }
});

export default router;
