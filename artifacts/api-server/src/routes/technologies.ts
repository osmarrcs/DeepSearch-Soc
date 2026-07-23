import { Router, type IRouter } from "express";
import { TECHNOLOGIES } from "../lib/technologies";

const router: IRouter = Router();

router.get("/technologies", async (_req, res): Promise<void> => {
  res.json(TECHNOLOGIES);
});

export default router;
