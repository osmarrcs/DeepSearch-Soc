import { Router, type IRouter } from "express";
import { desc, sql } from "drizzle-orm";
import { db, vulnerabilitiesTable, scansTable } from "@workspace/db";

const router: IRouter = Router();

router.get("/stats", async (_req, res): Promise<void> => {
  const [vulnStats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      pendentes: sql<number>`count(*) filter (where status = 'pendente')::int`,
      processados: sql<number>`count(*) filter (where status = 'processado')::int`,
      adiados: sql<number>`count(*) filter (where status = 'adiado')::int`,
      descartados: sql<number>`count(*) filter (where status = 'descartado')::int`,
      // CVSS >= 9 or "N/D (Exploração Ativa)"
      criticos: sql<number>`count(*) filter (where cvss = 'N/D (Exploração Ativa)' or (cvss ~ '^[0-9]+(\\.[0-9]+)?$' and cvss::float >= 9.0))::int`,
      altos: sql<number>`count(*) filter (where cvss ~ '^[0-9]+(\\.[0-9]+)?$' and cvss::float >= 7.0 and cvss::float < 9.0)::int`,
      medios: sql<number>`count(*) filter (where cvss ~ '^[0-9]+(\\.[0-9]+)?$' and cvss::float >= 4.0 and cvss::float < 7.0)::int`,
      baixos: sql<number>`count(*) filter (where cvss ~ '^[0-9]+(\\.[0-9]+)?$' and cvss::float < 4.0)::int`,
    })
    .from(vulnerabilitiesTable);

  const [scanStats] = await db
    .select({ totalScans: sql<number>`count(*)::int` })
    .from(scansTable);

  res.json({
    total: vulnStats.total ?? 0,
    pendentes: vulnStats.pendentes ?? 0,
    processados: vulnStats.processados ?? 0,
    adiados: vulnStats.adiados ?? 0,
    descartados: vulnStats.descartados ?? 0,
    criticos: vulnStats.criticos ?? 0,
    altos: vulnStats.altos ?? 0,
    medios: vulnStats.medios ?? 0,
    baixos: vulnStats.baixos ?? 0,
    totalScans: scanStats.totalScans ?? 0,
  });
});

router.get("/stats/by-tech", async (_req, res): Promise<void> => {
  const rows = await db
    .select({
      tech: vulnerabilitiesTable.tech,
      total: sql<number>`count(*)::int`,
      pendentes: sql<number>`count(*) filter (where status = 'pendente')::int`,
    })
    .from(vulnerabilitiesTable)
    .groupBy(vulnerabilitiesTable.tech)
    .orderBy(sql`count(*) desc`);

  res.json(rows);
});

router.get("/stats/by-source", async (_req, res): Promise<void> => {
  const rows = await db
    .select({
      source: vulnerabilitiesTable.source,
      total: sql<number>`count(*)::int`,
    })
    .from(vulnerabilitiesTable)
    .groupBy(vulnerabilitiesTable.source)
    .orderBy(sql`count(*) desc`);

  res.json(rows);
});

router.get("/stats/recent", async (_req, res): Promise<void> => {
  const rows = await db
    .select()
    .from(vulnerabilitiesTable)
    .orderBy(desc(vulnerabilitiesTable.foundAt))
    .limit(10);

  res.json(
    rows.map((v) => ({
      id: v.id,
      cveId: v.cveId,
      tech: v.tech,
      description: v.description,
      solution: v.solution,
      cvss: v.cvss,
      source: v.source,
      status: v.status,
      foundAt: v.foundAt instanceof Date ? v.foundAt.toISOString() : String(v.foundAt),
      scanId: v.scanId,
      triageNote: v.triageNote,
    }))
  );
});

export default router;
