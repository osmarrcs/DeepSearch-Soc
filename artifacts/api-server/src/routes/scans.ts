import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, scansTable, vulnerabilitiesTable } from "@workspace/db";
import {
  GetScanParams,
  CreateScanBody,
} from "@workspace/api-zod";
import { searchCisaKev, searchOsvDev, searchCircl, searchNvd } from "../lib/scanner";
import { logger } from "../lib/logger";

const router: IRouter = Router();

router.get("/scans", async (_req, res): Promise<void> => {
  const scans = await db
    .select()
    .from(scansTable)
    .orderBy(desc(scansTable.startedAt));
  res.json(scans.map(serializeScan));
});

router.post("/scans", async (req, res): Promise<void> => {
  const body = CreateScanBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      status: "em_andamento",
      technologies: body.data.technologies,
      totalFound: 0,
    })
    .returning();

  // Run the scan in the background
  runScan(scan.id, body.data.technologies).catch((err) => {
    logger.error({ err, scanId: scan.id }, "Scan failed unexpectedly");
  });

  res.status(201).json(serializeScan(scan));
});

router.get("/scans/:id", async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "Varredura não encontrada" });
    return;
  }
  res.json(serializeScan(scan));
});

async function runScan(scanId: number, technologies: string[]): Promise<void> {
  try {
    logger.info({ scanId, count: technologies.length }, "Starting scan");
    // Collect all existing processed CVE IDs to avoid duplicates
    const existing = await db
      .select({ cveId: vulnerabilitiesTable.cveId })
      .from(vulnerabilitiesTable);
    const processedIds = new Set(existing.map((e) => e.cveId));

    const seen = new Set<string>();
    let totalFound = 0;

    for (const tech of technologies) {
      const results = [
        ...(await searchCisaKev(tech)),
        ...(await searchOsvDev(tech)),
        ...(await searchCircl(tech)),
        ...(await searchNvd(tech)),
      ];

      for (const cve of results) {
        if (!cve.id || processedIds.has(cve.id) || seen.has(cve.id)) continue;
        seen.add(cve.id);
        await db.insert(vulnerabilitiesTable).values({
          cveId: cve.id,
          tech: cve.tech,
          description: cve.desc,
          solution: cve.solution,
          cvss: cve.cvss,
          source: cve.source,
          status: "pendente",
          scanId,
        });
        totalFound++;
      }
    }

    await db
      .update(scansTable)
      .set({ status: "concluido", completedAt: new Date(), totalFound })
      .where(eq(scansTable.id, scanId));

    logger.info({ scanId, totalFound }, "Scan completed");
  } catch (err) {
    logger.error({ err, scanId }, "Scan error");
    await db
      .update(scansTable)
      .set({ status: "erro", completedAt: new Date() })
      .where(eq(scansTable.id, scanId));
  }
}

function serializeScan(s: typeof scansTable.$inferSelect) {
  return {
    id: s.id,
    status: s.status,
    startedAt: s.startedAt instanceof Date ? s.startedAt.toISOString() : String(s.startedAt),
    completedAt: s.completedAt instanceof Date ? s.completedAt.toISOString() : (s.completedAt ? String(s.completedAt) : null),
    technologies: s.technologies ?? [],
    totalFound: s.totalFound,
  };
}

export default router;
