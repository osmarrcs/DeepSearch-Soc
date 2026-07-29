import { Router, type IRouter } from "express";
import healthRouter from "./health";
import technologiesRouter from "./technologies";
import vulnerabilitiesRouter from "./vulnerabilities";
import scansRouter from "./scans";
import statsRouter from "./stats";
import reportsRouter from "./reports";

const router: IRouter = Router();

router.use(healthRouter);
router.use(technologiesRouter);
router.use(vulnerabilitiesRouter);
router.use(scansRouter);
router.use(statsRouter);
router.use(reportsRouter);

export default router;
