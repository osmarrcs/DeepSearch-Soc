import { Router, type IRouter } from "express";
import { and, desc, eq, db, vulnerabilitiesTable } from "@workspace/db";
import {
  ListVulnerabilitiesQueryParams,
  GetVulnerabilityParams,
  TriageVulnerabilityParams,
  TriageVulnerabilityBody,
  GetVulnerabilityReportParams,
} from "@workspace/api-zod";
import { generateProfessionalReport } from "../lib/threat-intelligence";

const router: IRouter = Router();

router.get("/vulnerabilities", async (req, res): Promise<void> => {
  const query = ListVulnerabilitiesQueryParams.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: query.error.message });
    return;
  }
  const { status, tech, source, scanId } = query.data;

  const conditions = [];
  if (status) conditions.push(eq(vulnerabilitiesTable.status, status));
  if (tech) conditions.push(eq(vulnerabilitiesTable.tech, tech));
  if (source) conditions.push(eq(vulnerabilitiesTable.source, source));
  if (scanId != null) conditions.push(eq(vulnerabilitiesTable.scanId, scanId));

  const rows = await db
    .select()
    .from(vulnerabilitiesTable)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(vulnerabilitiesTable.foundAt));

  res.json(rows.map(serializeVuln));
});

router.get("/vulnerabilities/:id", async (req, res): Promise<void> => {
  const params = GetVulnerabilityParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [vuln] = await db
    .select()
    .from(vulnerabilitiesTable)
    .where(eq(vulnerabilitiesTable.id, params.data.id));
  if (!vuln) {
    res.status(404).json({ error: "Vulnerabilidade não encontrada" });
    return;
  }
  res.json(serializeVuln(vuln));
});

router.patch("/vulnerabilities/:id/triage", async (req, res): Promise<void> => {
  const params = TriageVulnerabilityParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const body = TriageVulnerabilityBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }

  const update: Record<string, string> = { status: body.data.status };
  if (body.data.triageNote != null) update.triageNote = body.data.triageNote;

  const [updated] = await db
    .update(vulnerabilitiesTable)
    .set(update)
    .where(eq(vulnerabilitiesTable.id, params.data.id))
    .returning();

  if (!updated) {
    res.status(404).json({ error: "Vulnerabilidade não encontrada" });
    return;
  }
  res.json(serializeVuln(updated));
});

router.get("/vulnerabilities/:id/report", async (req, res): Promise<void> => {
  const params = GetVulnerabilityReportParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [vuln] = await db
    .select()
    .from(vulnerabilitiesTable)
    .where(eq(vulnerabilitiesTable.id, params.data.id));
  if (!vuln) {
    res.status(404).json({ error: "Vulnerabilidade não encontrada" });
    return;
  }
  const report = await generateProfessionalReport({
    cveId: vuln.cveId,
    tech: vuln.tech,
    source: vuln.source,
    description: vuln.description,
    solution: vuln.solution,
    cvss: vuln.cvss,
  });

  res.json({
    html: report.html,
    vulnerability: serializeVuln(vuln),
    analysis: report.analysis,
    modelUsed: report.modelUsed,
    cacheHit: report.cacheHit,
    resolvedTechnology: report.resolvedTechnology,
    sources: report.sources,
  });
});

function serializeVuln(v: typeof vulnerabilitiesTable.$inferSelect) {
  return {
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
  };
}

export default router;
