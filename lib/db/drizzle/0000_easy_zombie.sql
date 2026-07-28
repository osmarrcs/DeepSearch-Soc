CREATE TABLE "scans" (
	"id" serial PRIMARY KEY NOT NULL,
	"status" text DEFAULT 'em_andamento' NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"technologies" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"total_found" integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vulnerabilities" (
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
