import { pgTable, text, serial, timestamp, integer, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("em_andamento"), // em_andamento | concluido | erro
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  technologies: jsonb("technologies").$type<string[]>().notNull().default([]),
  totalFound: integer("total_found").notNull().default(0),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, startedAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
