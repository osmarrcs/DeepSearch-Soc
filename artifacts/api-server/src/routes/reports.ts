import { Router, type IRouter } from "express";
import { generateRedHatReport, logRedHatReport } from "../lib/redhat-report";
import { generateMicrosoftPatchTuesdayReport } from "../lib/microsoft-report";
import { logger } from "../lib/logger";

const router: IRouter = Router();

interface ReportPeriodBody {
  startDate?: unknown;
  endDate?: unknown;
}

router.post("/reports/redhat", async (req, res): Promise<void> => {
  const body = (req.body ?? {}) as ReportPeriodBody;

  try {
    const result = await generateRedHatReport(body.startDate, body.endDate);
    logRedHatReport(result);
    res.json(result);
  } catch (error) {
    logger.error({ error, body }, "Red Hat report generation failed");
    res.status(502).json({
      error: error instanceof Error ? error.message : "Falha ao gerar o relatório Red Hat.",
    });
  }
});

router.post("/reports/microsoft", async (req, res): Promise<void> => {
  const body = (req.body ?? {}) as ReportPeriodBody;

  try {
    const result = await generateMicrosoftPatchTuesdayReport(body.startDate, body.endDate);
    res.json(result);
  } catch (error) {
    logger.error({ error, body }, "Microsoft Patch Tuesday report generation failed");
    res.status(502).json({
      error: error instanceof Error ? error.message : "Falha ao gerar o relatório Microsoft Patch Tuesday.",
    });
  }
});

export default router;
