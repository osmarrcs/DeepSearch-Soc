import { Router, type IRouter } from "express";
import { db, scansTable, vulnerabilitiesTable, desc, eq } from "@workspace/db";
import { GetScanParams, CreateScanBody } from "@workspace/api-zod";
import {
  defaultScanWindow,
  mapWithConcurrency,
  searchTechnology,
  type CveResult,
  type ScanQueryOptions,
} from "../lib/scanner";
import { TECHNOLOGIES } from "../lib/technologies";
import { logger } from "../lib/logger";

const router: IRouter = Router();
const SCAN_TECH_CONCURRENCY = readConcurrency();

router.get("/scans", async (_req, res): Promise<void> => {
  const scans = await db.select().from(scansTable).orderBy(desc(scansTable.startedAt));
  res.json(scans.map(serializeScan));
});

router.post("/scans", async (req, res): Promise<void> => {
  const body = CreateScanBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const defaults = defaultScanWindow();
  const options: ScanQueryOptions = {
    startDate: body.data.startDate ?? defaults.startDate,
    endDate: body.data.endDate ?? defaults.endDate,
    sources: body.data.sources ?? defaults.sources,
  };

  const startTime = new Date(`${options.startDate}T00:00:00Z`).getTime();
  const endTime = new Date(`${options.endDate}T23:59:59Z`).getTime();

  if (!Number.isFinite(startTime) || !Number.isFinite(endTime) || startTime > endTime) {
    res.status(400).json({ error: "Informe um período válido." });
    return;
  }

  const periodDays = Math.ceil((endTime - startTime) / 86_400_000);
  if (options.sources.includes("nvd") && periodDays > 120) {
    res.status(400).json({ error: "Consultas NVD permitem no máximo 120 dias por varredura." });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      status: "em_andamento",
      technologies: body.data.technologies,
      sources: options.sources,
      periodStart: options.startDate,
      periodEnd: options.endDate,
      totalFound: 0,
    })
    .returning();

  runScan(scan.id, body.data.technologies, options).catch((err) => {
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
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.id));
  if (!scan) {
    res.status(404).json({ error: "Varredura não encontrada" });
    return;
  }
  res.json(serializeScan(scan));
});

async function runScan(
  scanId: number,
  technologyIds: string[],
  options: ScanQueryOptions,
): Promise<void> {
  try {
    const targets = technologyIds.map((id) => ({
      id,
      name: TECHNOLOGIES.find((technology) => technology.id === id)?.name ?? id,
    }));

    logger.info(
      {
        scanId,
        count: targets.length,
        concurrency: SCAN_TECH_CONCURRENCY,
        period: `${options.startDate}..${options.endDate}`,
        sources: options.sources,
      },
      "Starting parallel scan",
    );

    const existing = await db
      .select({ cveId: vulnerabilitiesTable.cveId })
      .from(vulnerabilitiesTable);
    const processedIds = new Set(existing.map((item) => item.cveId.toUpperCase()));

    const resultGroups = await mapWithConcurrency(
      targets,
      SCAN_TECH_CONCURRENCY,
      async (target, index) => {
        const startedAt = Date.now();
        const results = await searchTechnology(target.name, options);
        logger.info(
          {
            scanId,
            technology: target.name,
            position: index + 1,
            total: targets.length,
            found: results.length,
            durationMs: Date.now() - startedAt,
          },
          "Technology scan completed",
        );
        return results;
      },
    );

    const merged = mergeAcrossTechnologies(resultGroups.flat());
    const newItems = merged.filter((item) => !processedIds.has(item.id.toUpperCase()));

    for (let index = 0; index < newItems.length; index += 100) {
      const chunk = newItems.slice(index, index + 100);
      if (!chunk.length) continue;
      await db.insert(vulnerabilitiesTable).values(
        chunk.map((cve) => ({
          cveId: cve.id,
          tech: cve.tech,
          description: cve.desc,
          solution: cve.solution,
          cvss: cve.cvss,
          source: cve.source,
          status: "pendente",
          scanId,
        })),
      );
    }

    await db
      .update(scansTable)
      .set({ status: "concluido", completedAt: new Date(), totalFound: newItems.length })
      .where(eq(scansTable.id, scanId));

    logger.info({ scanId, totalFound: newItems.length }, "Scan completed");
  } catch (err) {
    logger.error({ err, scanId }, "Scan error");
    await db
      .update(scansTable)
      .set({ status: "erro", completedAt: new Date() })
      .where(eq(scansTable.id, scanId));
  }
}

function mergeAcrossTechnologies(results: CveResult[]): CveResult[] {
  const seen = new Map<string, CveResult>();

  for (const result of results) {
    const key = result.id.toUpperCase();
    const previous = seen.get(key);
    if (!previous) {
      seen.set(key, { ...result, id: key });
      continue;
    }

    const previousScore = numericCvss(previous.cvss);
    const currentScore = numericCvss(result.cvss);
    const currentHasBetterScore =
      currentScore !== null && (previousScore === null || currentScore > previousScore);

    seen.set(key, {
      ...previous,
      tech: previous.tech === result.tech ? previous.tech : `${previous.tech}, ${result.tech}`,
      desc: result.desc.length > previous.desc.length ? result.desc : previous.desc,
      solution: result.source.includes("CISA") ? result.solution : previous.solution,
      cvss: currentHasBetterScore ? result.cvss : previous.cvss,
      source: Array.from(
        new Set([...previous.source.split(" + "), ...result.source.split(" + ")]),
      ).join(" + "),
    });
  }

  return [...seen.values()];
}

function numericCvss(value: string): number | null {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function readConcurrency(): number {
  const parsed = Number(process.env["SCAN_TECH_CONCURRENCY"]);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 10 ? parsed : 4;
}

function serializeScan(s: typeof scansTable.$inferSelect) {
  return {
    id: s.id,
    status: s.status,
    startedAt: s.startedAt instanceof Date ? s.startedAt.toISOString() : String(s.startedAt),
    completedAt:
      s.completedAt instanceof Date
        ? s.completedAt.toISOString()
        : s.completedAt
          ? String(s.completedAt)
          : null,
    technologies: s.technologies ?? [],
    sources: s.sources ?? [],
    periodStart: s.periodStart,
    periodEnd: s.periodEnd,
    totalFound: s.totalFound,
  };
}

export default router;
