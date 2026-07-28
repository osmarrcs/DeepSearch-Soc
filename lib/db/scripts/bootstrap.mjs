import pg from "pg";

const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL must be set before running db:bootstrap");
}

const isLocal = /localhost|127\.0\.0\.1/.test(connectionString);

const pool = new Pool({
  connectionString,
  ssl: isLocal ? false : { rejectUnauthorized: false },
  max: 1,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 10_000,
});

const createOrRepairSchemaSql = `
CREATE TABLE IF NOT EXISTS "scans" (
  "id" serial PRIMARY KEY NOT NULL,
  "status" text DEFAULT 'em_andamento' NOT NULL,
  "started_at" timestamp with time zone DEFAULT now() NOT NULL,
  "completed_at" timestamp with time zone,
  "technologies" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "total_found" integer DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS "vulnerabilities" (
  "id" serial PRIMARY KEY NOT NULL,
  "cve_id" text NOT NULL,
  "tech" text NOT NULL,
  "description" text NOT NULL,
  "solution" text NOT NULL,
  "cvss" text NOT NULL,
  "source" text NOT NULL,
  "status" text DEFAULT 'pendente' NOT NULL,
  "found_at" timestamp with time zone DEFAULT now() NOT NULL,
  "scan_id" integer,
  "triage_note" text
);

ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "status" text DEFAULT 'em_andamento' NOT NULL;
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "started_at" timestamp with time zone DEFAULT now() NOT NULL;
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "completed_at" timestamp with time zone;
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "technologies" jsonb DEFAULT '[]'::jsonb NOT NULL;
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "total_found" integer DEFAULT 0 NOT NULL;

ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "cve_id" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "tech" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "description" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "solution" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "cvss" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "source" text DEFAULT '' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "status" text DEFAULT 'pendente' NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "found_at" timestamp with time zone DEFAULT now() NOT NULL;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "scan_id" integer;
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "triage_note" text;
`;

const normalizeTechnologiesSql = `
CREATE OR REPLACE FUNCTION public.deepsearch_soc_to_jsonb_array(value text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  cleaned text;
BEGIN
  IF value IS NULL OR btrim(value) = '' THEN
    RETURN '[]'::jsonb;
  END IF;

  cleaned := btrim(value);

  IF left(cleaned, 1) = '[' THEN
    RETURN cleaned::jsonb;
  END IF;

  cleaned := regexp_replace(cleaned, '^\\{|\\}$', '', 'g');
  cleaned := replace(cleaned, '"', '');

  IF btrim(cleaned) = '' THEN
    RETURN '[]'::jsonb;
  END IF;

  RETURN to_jsonb(string_to_array(cleaned, ','));
END;
$$;

CREATE OR REPLACE FUNCTION public.deepsearch_soc_text_array_to_jsonb(value text[])
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT to_jsonb(COALESCE(value, ARRAY[]::text[]));
$$;

DO $$
DECLARE
  technologies_type text;
BEGIN
  SELECT udt_name
    INTO technologies_type
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name = 'scans'
    AND column_name = 'technologies';

  IF technologies_type IS NULL THEN
    RAISE EXCEPTION 'Column public.scans.technologies was not found';
  END IF;

  ALTER TABLE "scans" ALTER COLUMN "technologies" DROP DEFAULT;

  IF technologies_type = 'jsonb' THEN
    UPDATE "scans"
      SET "technologies" = '[]'::jsonb
      WHERE "technologies" IS NULL;
  ELSIF technologies_type = '_text' THEN
    ALTER TABLE "scans"
      ALTER COLUMN "technologies" TYPE jsonb
      USING public.deepsearch_soc_text_array_to_jsonb("technologies");
  ELSIF technologies_type IN ('json', 'text', 'varchar', 'bpchar') THEN
    ALTER TABLE "scans"
      ALTER COLUMN "technologies" TYPE jsonb
      USING public.deepsearch_soc_to_jsonb_array("technologies"::text);
  ELSE
    RAISE EXCEPTION 'Unsupported public.scans.technologies type: %', technologies_type;
  END IF;

  ALTER TABLE "scans" ALTER COLUMN "technologies" SET DEFAULT '[]'::jsonb;
  ALTER TABLE "scans" ALTER COLUMN "technologies" SET NOT NULL;
END $$;

DROP FUNCTION public.deepsearch_soc_to_jsonb_array(text);
DROP FUNCTION public.deepsearch_soc_text_array_to_jsonb(text[]);
`;

try {
  await pool.query("BEGIN");
  await pool.query(createOrRepairSchemaSql);
  await pool.query(normalizeTechnologiesSql);
  await pool.query("COMMIT");
  console.log("[db] bootstrap complete");
} catch (error) {
  await pool.query("ROLLBACK").catch(() => undefined);
  console.error("[db] bootstrap failed", error);
  process.exitCode = 1;
} finally {
  await pool.end();
}