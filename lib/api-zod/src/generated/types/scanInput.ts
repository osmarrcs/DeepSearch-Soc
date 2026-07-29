/** Generated compatibility type. */
export interface ScanInput {
  technologies: string[];
  startDate?: string;
  endDate?: string;
  sources?: Array<"nvd" | "cisa" | "circl" | "osv">;
}
