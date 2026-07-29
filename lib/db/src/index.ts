import { drizzle } from "drizzle-orm/node-postgres";
import { and, desc, eq, sql } from "drizzle-orm/sql";
import pg from "pg";
import * as schema from "./schema";

export { and, desc, eq, sql };

const { Pool } = pg;

const rawDatabaseUrl = process.env.DATABASE_URL?.trim();

if (!rawDatabaseUrl) {
  throw new Error(
    "DATABASE_URL must be set. Configure the Supabase pooler URI in Render.",
  );
}

/**
 * Valida e normaliza a URL antes de entregá-la ao node-postgres.
 *
 * Motivos:
 * - detecta URLs malformadas, como a ausência de @ entre senha e hostname;
 * - evita configurar SSL duas vezes (objeto `ssl` + `sslmode` na URL);
 * - mantém uma única política TLS definida no código.
 */
function normalizeDatabaseUrl(value: string): {
  connectionString: string;
  isLocal: boolean;
} {
  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch (error) {
    throw new Error(
      "DATABASE_URL inválida. Copie novamente a URI do Supabase. " +
        "Ela deve conter @ antes do hostname do pooler.",
      { cause: error },
    );
  }

  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)) {
    throw new Error(
      `DATABASE_URL deve usar postgres:// ou postgresql://, recebido: ${parsed.protocol}`,
    );
  }

  if (!parsed.username || !parsed.hostname || !parsed.pathname) {
    throw new Error(
      "DATABASE_URL incompleta: usuário, hostname e banco são obrigatórios.",
    );
  }

  const isLocal = /localhost|127\.0\.0\.1/.test(parsed.hostname);

  // O node-postgres substitui o objeto `ssl` quando `sslmode` aparece na URL.
  // Removemos parâmetros SSL da URI e aplicamos a política explicitamente abaixo.
  for (const key of [
    "sslmode",
    "sslcert",
    "sslkey",
    "sslrootcert",
    "sslnegotiation",
  ]) {
    parsed.searchParams.delete(key);
  }

  return {
    connectionString: parsed.toString(),
    isLocal,
  };
}

const { connectionString, isLocal } = normalizeDatabaseUrl(rawDatabaseUrl);

export const pool = new Pool({
  connectionString,
  // Render encerra HTTPS na borda. Este SSL é exclusivamente para Postgres.
  // O tráfego fica criptografado. Para validação estrita, forneça a CA do
  // Supabase e altere rejectUnauthorized para true.
  ssl: isLocal ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  keepAlive: true,
});

pool.on("error", (err) => {
  // Um erro em cliente ocioso não deve derrubar o processo sem diagnóstico.
  console.error("[db] idle client error", err);
});

export const db = drizzle(pool, { schema });

export * from "./schema";
