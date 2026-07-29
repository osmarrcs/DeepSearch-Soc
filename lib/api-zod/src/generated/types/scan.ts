/** Generated compatibility type. */
import type { ScanStatus } from './scanStatus';
export interface Scan {
  id: number;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string | null;
  technologies: string[];
  sources?: Array<"nvd" | "cisa" | "circl" | "osv">;
  periodStart?: string | null;
  periodEnd?: string | null;
  totalFound: number;
}
