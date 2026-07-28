import { drizzle } from "drizzle-orm/node-postgres";
import { and, desc, eq, sql } from "drizzle-orm/sql";
import pg from "pg";
import * as schema from "./schema";

export { and, desc, eq, sql };

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

// Compatível com Supabase (recomendado — free), Neon, Railway e Postgres local.
// Postgres serverless (Supabase pooler / Neon) exige TLS; o driver `pg` NÃO
// ativa SSL só porque a URL contém `sslmode=require`.
const connectionString = process.env.DATABASE_URL;
const isLocal = /localhost|127\.0\.0\.1/.test(connectionString);

export const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
  // Pools pequenos + idle curto evitam sockets mortos quando o Supabase/Neon
  // suspende compute ou o pgbouncer da Supabase recicla conexões.
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

// Sem esse listener, um erro idle vindo do Postgres derruba o processo Node.
pool.on("error", (err) => {
  // eslint-disable-next-line no-console
  console.error("[db] idle client error", err);
});

export const db = drizzle(pool, { schema });

export * from "./schema";
