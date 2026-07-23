import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const vulnerabilitiesTable = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  cveId: text("cve_id").notNull(),
  tech: text("tech").notNull(),
  description: text("description").notNull(),
  solution: text("solution").notNull(),
  cvss: text("cvss").notNull(),
  source: text("source").notNull(),
  status: text("status").notNull().default("pendente"), // pendente | processado | adiado | descartado
  foundAt: timestamp("found_at", { withTimezone: true }).notNull().defaultNow(),
  scanId: integer("scan_id"),
  triageNote: text("triage_note"),
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilitiesTable).omit({ id: true, foundAt: true });
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilitiesTable.$inferSelect;
