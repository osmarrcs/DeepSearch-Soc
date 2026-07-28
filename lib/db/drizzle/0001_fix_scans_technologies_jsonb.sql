-- Normaliza o schema usado pelo endpoint POST /api/scans em produção.
-- O erro 500 acontecia quando o banco estava com "scans.technologies"
-- em um tipo diferente do esperado pelo código. JSONB é mais previsível para
-- arrays vindos do JavaScript/Express e continua retornando string[] para o front.

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

  -- Aceita também literais de array Postgres como {"google-chrome","mozilla-firefox"}.
  cleaned := regexp_replace(cleaned, '^\{|\}$', '', 'g');
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