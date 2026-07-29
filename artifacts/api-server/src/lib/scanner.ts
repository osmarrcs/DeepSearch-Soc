import { logger } from "./logger";

export interface CveResult {
  id: string;
  tech: string;
  desc: string;
  solution: string;
  cvss: string;
  source: string;
}

export type ScanSource = "nvd" | "cisa" | "circl" | "osv";

export interface ScanQueryOptions {
  startDate: string;
  endDate: string;
  sources: ScanSource[];
}

const NVD_API_KEY = process.env["NVD_API_KEY"]?.trim() ?? "";
const NVD_RESULTS_PER_TECH = readPositiveInt("NVD_RESULTS_PER_TECH", 20, 1, 100);
const DEFAULT_SCAN_DAYS = readPositiveInt("SCAN_DAYS", 3, 1, 120);

const CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CISA_CACHE_TTL_MS = 15 * 60 * 1000;

export interface CisaKevItem {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
}

let cisaCache: { expiresAt: number; items: CisaKevItem[] } | null = null;
let cisaPromise: Promise<CisaKevItem[]> | null = null;

// A fila global respeita a janela da NVD. Com chave: aproximadamente 50
// chamadas/30 s. Sem chave: aproximadamente 5 chamadas/30 s.
let nvdQueue: Promise<void> = Promise.resolve();
let nvdNextRequestAt = 0;

function readPositiveInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number(process.env[name]);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) return fallback;
  return parsed;
}

export function getScannerConfig() {
  return {
    nvdApiKeyConfigured: Boolean(NVD_API_KEY),
    nvdResultsPerTech: NVD_RESULTS_PER_TECH,
    defaultScanDays: DEFAULT_SCAN_DAYS,
    defaultSources: ["nvd", "cisa"],
    optionalSources: ["circl", "osv"],
  };
}

export function defaultScanWindow(): ScanQueryOptions {
  const end = new Date();
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - DEFAULT_SCAN_DAYS);
  return {
    startDate: start.toISOString().slice(0, 10),
    endDate: end.toISOString().slice(0, 10),
    sources: ["nvd", "cisa"],
  };
}

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 12000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function waitForNvdSlot(): Promise<void> {
  const intervalMs = NVD_API_KEY ? 650 : 6200;
  const previous = nvdQueue;
  let release!: () => void;
  nvdQueue = new Promise<void>((resolve) => {
    release = resolve;
  });

  await previous;
  const waitMs = Math.max(0, nvdNextRequestAt - Date.now());
  if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
  nvdNextRequestAt = Date.now() + intervalMs;
  release();
}

export async function getCisaKevFeed(): Promise<CisaKevItem[]> {
  if (cisaCache && cisaCache.expiresAt > Date.now()) return cisaCache.items;
  if (cisaPromise) return cisaPromise;

  cisaPromise = (async () => {
    try {
      const resp = await fetchWithTimeout(CISA_URL, {}, 15000);
      if (!resp.ok) throw new Error(`CISA KEV HTTP ${resp.status}`);
      const data = (await resp.json()) as { vulnerabilities?: CisaKevItem[] };
      const items = data.vulnerabilities ?? [];
      cisaCache = { expiresAt: Date.now() + CISA_CACHE_TTL_MS, items };
      return items;
    } catch (err) {
      logger.warn({ err }, "CISA KEV feed fetch failed");
      return cisaCache?.items ?? [];
    } finally {
      cisaPromise = null;
    }
  })();

  return cisaPromise;
}

export async function searchCisaKev(
  tech: string,
  options: ScanQueryOptions,
): Promise<CveResult[]> {
  const results: CveResult[] = [];
  const feed = await getCisaKevFeed();
  const { start, end } = parseDateRange(options.startDate, options.endDate);
  const terms = technologySearchTerms(tech);

  for (const vuln of feed) {
    const dateAdded = new Date(`${vuln.dateAdded ?? ""}T00:00:00.000Z`);
    if (Number.isNaN(dateAdded.getTime()) || dateAdded < start || dateAdded > end) continue;

    const haystack = `${vuln.vendorProject ?? ""} ${vuln.product ?? ""} ${vuln.vulnerabilityName ?? ""}`.toLowerCase();
    if (!terms.some((term) => haystack.includes(term))) continue;

    results.push({
      id: vuln.cveID ?? `CISA-${Date.now()}`,
      tech,
      desc: vuln.shortDescription ?? "Sem descrição disponível.",
      solution: vuln.requiredAction ?? "Aplicar correção conforme orientação do fabricante.",
      cvss: "N/D (Exploração Ativa)",
      source: "CISA KEV",
    });
  }

  return results;
}

const OSV_SKIP_TECHS = new Set([
  "fortigate", "fortimanager", "fortianalyzer", "forticlient ems",
  "cisco secure email", "senhasegura pam", "f5 big-ip", "aws",
  "openshift", "vmware", "kaspersky", "mcafee", "trellix",
  "openvpn", "zabbix", "pulse secure", "windows", "linux kernel",
  "microsoft sql server", "microsoft edge", "microsoft office",
  "adobe acrobat", "adobe photoshop", "autocad", "cribl stream",
]);

export async function searchOsvDev(tech: string): Promise<CveResult[]> {
  if (OSV_SKIP_TECHS.has(tech.toLowerCase())) return [];

  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(
      "https://api.osv.dev/v1/query",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ package: { name: normalizeOsvPackageName(tech) } }),
      },
      8000,
    );
    if (!resp.ok) return results;

    const data = (await resp.json()) as {
      vulns?: Array<{ id?: string; details?: string; summary?: string }>;
    };
    for (const vuln of (data.vulns ?? []).slice(0, 4)) {
      results.push({
        id: vuln.id ?? "OSV-VULN",
        tech,
        desc: vuln.details ?? vuln.summary ?? "Detalhes técnicos fornecidos na base OSV.",
        solution: "Atualizar o pacote afetado conforme o advisory do projeto.",
        cvss: "N/D",
        source: "OSV.dev",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "OSV.dev fetch failed");
  }
  return results;
}

export async function searchCircl(tech: string): Promise<CveResult[]> {
  const query = technologySearchTerms(tech)[0] ?? tech.toLowerCase();
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(
      `https://cve.circl.lu/api/vulnerability/fulltext?q=${encodeURIComponent(query)}`,
      { headers: { Accept: "application/json" } },
      9000,
    );
    if (!resp.ok) return results;

    const data = (await resp.json()) as {
      data?: Array<{
        cveMetadata?: { cveId?: string };
        containers?: { cna?: { descriptions?: Array<{ lang?: string; value?: string }> } };
      }>;
    };

    for (const vuln of (data.data ?? []).slice(0, 4)) {
      const descriptions = vuln.containers?.cna?.descriptions ?? [];
      const description =
        descriptions.find((d) => d.lang === "pt-BR" || d.lang === "pt")?.value
        ?? descriptions.find((d) => d.lang === "en")?.value
        ?? descriptions[0]?.value
        ?? "Sem descrição disponível.";

      results.push({
        id: String(vuln.cveMetadata?.cveId ?? `CIRCL-${Date.now()}`),
        tech,
        desc: description,
        solution: "Verificar o advisory oficial do fabricante.",
        cvss: "N/D",
        source: "CIRCL / CVE",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "CIRCL fetch failed");
  }
  return results;
}

export async function searchNvd(
  tech: string,
  options: ScanQueryOptions,
): Promise<CveResult[]> {
  const results: CveResult[] = [];
  try {
    const { start, end } = parseDateRange(options.startDate, options.endDate);
    const params = new URLSearchParams({
      pubStartDate: start.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      pubEndDate: end.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      keywordSearch: tech,
      resultsPerPage: String(NVD_RESULTS_PER_TECH),
    });

    await waitForNvdSlot();

    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "DeepSearch-SOC/12.0",
    };
    if (NVD_API_KEY) headers.apiKey = NVD_API_KEY;

    const resp = await fetchWithTimeout(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`,
      { headers },
      25000,
    );

    if (!resp.ok) {
      logger.warn({ tech, status: resp.status }, "NVD request returned non-OK status");
      return results;
    }

    const data = (await resp.json()) as {
      vulnerabilities?: Array<{ cve: Record<string, unknown> }>;
    };

    for (const item of data.vulnerabilities ?? []) {
      const cve = item.cve;
      const descriptions = cve["descriptions"] as Array<{ lang?: string; value?: string }> | undefined;
      const desc =
        descriptions?.find((d) => d.lang === "pt-BR" || d.lang === "pt")?.value
        ?? descriptions?.find((d) => d.lang === "en")?.value
        ?? descriptions?.[0]?.value
        ?? "Sem descrição disponível.";

      results.push({
        id: String(cve["id"] ?? ""),
        tech,
        desc,
        solution: "Aplicar as atualizações de segurança e mitigações publicadas pelo fabricante.",
        cvss: extractNvdCvss(cve["metrics"]),
        source: "NVD / NIST",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "NVD fetch failed");
  }
  return results;
}

export async function searchTechnology(
  tech: string,
  options: ScanQueryOptions,
): Promise<CveResult[]> {
  const selected = new Set(options.sources);
  const tasks: Array<Promise<CveResult[]>> = [];

  if (selected.has("cisa")) tasks.push(searchCisaKev(tech, options));
  if (selected.has("nvd")) tasks.push(searchNvd(tech, options));
  if (selected.has("circl")) tasks.push(searchCircl(tech));
  if (selected.has("osv")) tasks.push(searchOsvDev(tech));

  const settled = await Promise.allSettled(tasks);
  const combined = settled.flatMap((result) =>
    result.status === "fulfilled" ? result.value : [],
  );
  return mergeCveResults(combined);
}

export async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  async function runWorker() {
    while (true) {
      const index = nextIndex++;
      if (index >= items.length) return;
      results[index] = await worker(items[index]!, index);
    }
  }

  const workerCount = Math.min(Math.max(1, concurrency), items.length || 1);
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  return results;
}

function mergeCveResults(results: CveResult[]): CveResult[] {
  const merged = new Map<string, CveResult>();

  for (const current of results) {
    if (!current.id) continue;
    const key = current.id.toUpperCase();
    const previous = merged.get(key);
    if (!previous) {
      merged.set(key, { ...current, id: key });
      continue;
    }

    const previousNumeric = numericCvss(previous.cvss);
    const currentNumeric = numericCvss(current.cvss);
    const preferCurrentDescription = current.source.includes("NVD") || current.desc.length > previous.desc.length;

    merged.set(key, {
      ...previous,
      desc: preferCurrentDescription ? current.desc : previous.desc,
      solution: current.source.includes("CISA") ? current.solution : previous.solution,
      cvss:
        currentNumeric !== null && (previousNumeric === null || currentNumeric > previousNumeric)
          ? current.cvss
          : previous.cvss,
      source: Array.from(new Set([...previous.source.split(" + "), ...current.source.split(" + ")])).join(" + "),
    });
  }

  return [...merged.values()];
}

function parseDateRange(startDate: string, endDate: string): { start: Date; end: Date } {
  const start = new Date(`${startDate}T00:00:00.000Z`);
  const end = new Date(`${endDate}T23:59:59.999Z`);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    throw new Error("Período de consulta inválido");
  }
  return { start, end };
}

function extractNvdCvss(metricsValue: unknown): string {
  const metrics = metricsValue as Record<string, unknown> | undefined;
  if (!metrics) return "N/D";

  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const entries = metrics[key] as Array<{ cvssData?: { baseScore?: number } }> | undefined;
    const score = entries?.[0]?.cvssData?.baseScore;
    if (score !== undefined && score !== null) return String(score);
  }
  return "N/D";
}

function numericCvss(value: string): number | null {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function normalizeOsvPackageName(tech: string): string {
  const aliases: Record<string, string> = {
    "7-Zip": "7zip",
    "Visual Studio Code": "vscode",
    "JetBrains IDEs": "jetbrains",
    "Mozilla Firefox": "firefox",
    "Google Chrome": "chromium",
  };
  return aliases[tech] ?? tech.toLowerCase();
}

function technologySearchTerms(tech: string): string[] {
  const aliases: Record<string, string[]> = {
    FortiGate: ["fortigate", "fortios"],
    FortiManager: ["fortimanager"],
    FortiAnalyzer: ["fortianalyzer"],
    "FortiClient EMS": ["forticlient ems", "forticlient"],
    "Cisco Secure Email": ["cisco secure email", "email security appliance"],
    "senhasegura PAM": ["senhasegura"],
    "F5 BIG-IP": ["big-ip", "f5"],
    OpenShift: ["openshift"],
    VMware: ["vmware", "broadcom vmware"],
    "Pulse Secure": ["pulse secure", "ivanti connect secure"],
    Windows: ["microsoft windows", "windows"],
    "Linux Kernel": ["linux kernel"],
    "Microsoft SQL Server": ["sql server"],
    "Google Chrome": ["chrome", "chromium"],
    "Microsoft Edge": ["microsoft edge"],
    "7-Zip": ["7-zip", "7zip"],
    "Visual Studio Code": ["visual studio code", "vscode"],
    "Node.js": ["node.js", "nodejs"],
    "Microsoft Office": ["microsoft office"],
    "Adobe Acrobat": ["adobe acrobat", "acrobat reader"],
    "Cribl Stream": ["cribl stream"],
  };
  return (aliases[tech] ?? [tech]).map((term) => term.toLowerCase());
}
