import { fetchWithTimeout, getCisaKevFeed } from "./scanner";
import { logger } from "./logger";
import {
  arrayValue,
  escapeHtml,
  formatDatePt,
  numberValue,
  parseDateRange,
  safeText,
  severityColor,
  truncate,
  uniqueStrings,
} from "./report-utils";

const MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0";
const MSRC_API_VERSION = "2023-11-01";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

interface MsrcDocument extends Record<string, unknown> {}

export interface MicrosoftReportItem {
  cveId: string;
  title: string;
  impact: string;
  cvss: string;
  vector: string;
  severity: string;
  products: string[];
  kbArticles: string[];
  patchUrls: string[];
  restart: string;
  exploited: boolean;
  publiclyDisclosed: boolean;
  windowsFamily: boolean;
  releaseId: string;
}

export interface MicrosoftReportResult {
  html: string;
  startDate: string;
  endDate: string;
  releaseIds: string[];
  summary: {
    total: number;
    critical: number;
    important: number;
    exploited: number;
    publiclyDisclosed: number;
    clusters: Array<{ name: string; count: number }>;
  };
  items: MicrosoftReportItem[];
}

export async function generateMicrosoftPatchTuesdayReport(
  startDate: unknown,
  endDate: unknown,
): Promise<MicrosoftReportResult> {
  const range = parseDateRange(startDate, endDate, 370);
  const releaseIds = monthIdsBetween(range.start, range.end);
  const documents = await Promise.all(releaseIds.map(fetchMsrcDocument));
  const kev = await getCisaKevFeed();
  const kevIds = new Set(kev.map((item) => item.cveID).filter(Boolean));

  const items = documents
    .flatMap(({ id, document }) => normalizeDocument(id, document, kevIds))
    .filter((item, index, list) => list.findIndex((candidate) => candidate.cveId === item.cveId) === index)
    .sort((a, b) => {
      const rank = severityRank(b.severity) - severityRank(a.severity);
      if (rank !== 0) return rank;
      if (a.exploited !== b.exploited) return a.exploited ? -1 : 1;
      return (numberValue(b.cvss) ?? 0) - (numberValue(a.cvss) ?? 0);
    });

  const clusters = buildImpactClusters(items);
  const summary = {
    total: items.length,
    critical: items.filter((item) => item.severity === "Crítica").length,
    important: items.filter((item) => item.severity === "Importante").length,
    exploited: items.filter((item) => item.exploited).length,
    publiclyDisclosed: items.filter((item) => item.publiclyDisclosed).length,
    clusters,
  };

  const result: MicrosoftReportResult = {
    html: renderMicrosoftHtml(items, range.startDate, range.endDate, releaseIds, summary),
    startDate: range.startDate,
    endDate: range.endDate,
    releaseIds,
    summary,
    items,
  };

  logger.info({
    period: `${range.startDate}..${range.endDate}`,
    releases: releaseIds,
    total: summary.total,
    exploited: summary.exploited,
  }, "Microsoft Patch Tuesday report generated");

  return result;
}

async function fetchMsrcDocument(id: string): Promise<{ id: string; document: MsrcDocument }> {
  const urls = [
    `${MSRC_BASE}/cvrf/${encodeURIComponent(id)}?api-version=${MSRC_API_VERSION}`,
    `${MSRC_BASE}/cvrf/${encodeURIComponent(id)}`,
  ];
  let lastError = "";

  for (const url of urls) {
    try {
      const response = await fetchWithTimeout(
        url,
        {
          headers: {
            Accept: "application/json, text/json;q=0.9",
            "User-Agent": "DeepSearch-SOC/12.0",
          },
        },
        30000,
      );
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
        continue;
      }

      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      const text = await response.text();
      if (contentType.includes("json") || text.trimStart().startsWith("{")) {
        return { id, document: JSON.parse(text) as MsrcDocument };
      }

      lastError = "A API devolveu XML em vez de JSON";
    } catch (error) {
      lastError = error instanceof Error ? error.message : "Falha de consulta";
    }
  }

  throw new Error(`Não foi possível obter o documento MSRC ${id}: ${lastError}`);
}

function normalizeDocument(
  releaseId: string,
  document: MsrcDocument,
  kevIds: Set<string | undefined>,
): MicrosoftReportItem[] {
  const products = extractProductMap(document);
  const vulnerabilities = arrayValue<Record<string, unknown>>(
    document["Vulnerability"] ?? document["Vulnerabilities"] ?? document["vulnerability"],
  );

  return vulnerabilities.flatMap((raw) => {
    const cveId = safeText(raw["CVE"] ?? raw["Cve"] ?? raw["cve"], "").toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return [];

    const title = extractTextValue(raw["Title"]) || cveId;
    const threats = arrayValue<Record<string, unknown>>(raw["Threats"] ?? raw["Threat"]);
    const threatTexts = threats.map((threat) => extractTextValue(threat["Description"])).filter(Boolean);
    const scores = arrayValue<Record<string, unknown>>(raw["CVSSScoreSets"] ?? raw["CVSSScoreSet"]);
    const score = scores.map((entry) => numberValue(entry["BaseScore"] ?? entry["Score"])).find((value) => value !== null) ?? null;
    const vector = scores.map((entry) => safeText(entry["Vector"], "")).find(Boolean) || "N/A";

    const severity = inferSeverity(threatTexts, score);
    const impact = inferImpact(title, threatTexts);
    const exploited = kevIds.has(cveId) || threatTexts.some((text) => /exploitation detected|exploited\s*[:=-]?\s*yes|exploração detectada/i.test(text));
    const publiclyDisclosed = threatTexts.some((text) => /publicly disclosed\s*[:=-]?\s*yes|divulgad[oa] publicamente/i.test(text));

    const productIds = collectProductIds(raw);
    const productNames = uniqueStrings(productIds.map((id) => products.get(id) ?? id)).slice(0, 30);
    const remediations = arrayValue<Record<string, unknown>>(raw["Remediations"] ?? raw["Remediation"]);
    const kbArticles = uniqueStrings(remediations.map((item) => extractTextValue(item["Description"])).filter((value) => /KB\d+/i.test(value)));
    const patchUrls = uniqueStrings(remediations.map((item) => safeText(item["URL"] ?? item["Url"], ""))).filter((url) => /^https?:\/\//i.test(url));
    const restart = uniqueStrings(remediations.map((item) => extractRestart(item))).join(", ") || "Consultar atualização";
    const windowsFamily = productNames.some((name) => /windows|server|edge|office|exchange|sharepoint|sql server/i.test(name));

    return [{
      cveId,
      title,
      impact,
      cvss: score === null ? "N/A" : String(score),
      vector,
      severity,
      products: productNames,
      kbArticles,
      patchUrls,
      restart,
      exploited,
      publiclyDisclosed,
      windowsFamily,
      releaseId,
    }];
  });
}

function extractProductMap(document: MsrcDocument): Map<string, string> {
  const map = new Map<string, string>();

  function walk(value: unknown): void {
    if (Array.isArray(value)) {
      value.forEach(walk);
      return;
    }
    if (!value || typeof value !== "object") return;
    const object = value as Record<string, unknown>;

    const productId = safeText(object["ProductID"] ?? object["ProductId"] ?? object["productID"], "");
    const productName = extractTextValue(object["Value"] ?? object["Name"] ?? object["FullProductName"]);
    if (productId && productName) map.set(productId, productName);

    for (const [key, child] of Object.entries(object)) {
      if (/ProductTree|Branch|FullProductName|ProductFamilies|Relationship/i.test(key)) walk(child);
    }
  }

  walk(document["ProductTree"] ?? document["productTree"] ?? document);
  return map;
}

function collectProductIds(raw: Record<string, unknown>): string[] {
  const ids: string[] = [];

  function collect(value: unknown, keyHint = ""): void {
    if (Array.isArray(value)) {
      if (/ProductID/i.test(keyHint)) {
        value.forEach((entry) => {
          if (typeof entry === "string") ids.push(entry);
          else collect(entry, keyHint);
        });
      } else {
        value.forEach((entry) => collect(entry, keyHint));
      }
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/ProductID/i.test(key) && typeof child === "string") ids.push(child);
      else collect(child, key);
    }
  }

  collect(raw);
  return uniqueStrings(ids);
}

function extractTextValue(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) return value.map(extractTextValue).filter(Boolean).join("; ");
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return safeText(object["Value"] ?? object["value"] ?? object["Description"] ?? object["Title"], "");
  }
  return "";
}

function extractRestart(remediation: Record<string, unknown>): string {
  const value = remediation["RestartRequired"] ?? remediation["Restart"];
  const text = extractTextValue(value);
  if (text) return text;
  if (typeof value === "boolean") return value ? "Reinicialização necessária" : "Sem reinicialização";
  return "";
}

function inferSeverity(threatTexts: string[], score: number | null): string {
  const text = threatTexts.join(" ");
  if (/critical|crític/i.test(text) || (score ?? 0) >= 9) return "Crítica";
  if (/important|high|alta/i.test(text) || (score ?? 0) >= 7) return "Importante";
  if (/moderate|medium|média/i.test(text) || (score ?? 0) >= 4) return "Moderada";
  return "Baixa";
}

function inferImpact(title: string, threatTexts: string[]): string {
  const candidates = threatTexts.filter((text) =>
    !/critical|important|moderate|low|exploitation|publicly disclosed|severity/i.test(text),
  );
  return candidates[0] || title;
}

function severityRank(value: string): number {
  if (value === "Crítica") return 4;
  if (value === "Importante") return 3;
  if (value === "Moderada") return 2;
  return 1;
}

function buildImpactClusters(items: MicrosoftReportItem[]): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const value = normalizeImpact(item.impact || item.title);
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function normalizeImpact(value: string): string {
  const lower = value.toLowerCase();
  if (/remote code execution|execução remota/.test(lower)) return "Execução Remota de Código";
  if (/elevation of privilege|elevação de privilégio/.test(lower)) return "Elevação de Privilégio";
  if (/information disclosure|divulgação de informação/.test(lower)) return "Divulgação de Informações";
  if (/denial of service|negação de serviço/.test(lower)) return "Negação de Serviço";
  if (/security feature bypass|bypass/.test(lower)) return "Bypass de Recurso de Segurança";
  if (/spoofing/.test(lower)) return "Spoofing";
  if (/tampering/.test(lower)) return "Adulteração";
  return truncate(value, 70) || "Outros";
}

function monthIdsBetween(start: Date, end: Date): string[] {
  const cursor = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), 1));
  const limit = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 1));
  const ids: string[] = [];
  while (cursor <= limit) {
    ids.push(`${cursor.getUTCFullYear()}-${MONTHS[cursor.getUTCMonth()]}`);
    cursor.setUTCMonth(cursor.getUTCMonth() + 1);
  }
  return ids;
}

function renderMicrosoftHtml(
  items: MicrosoftReportItem[],
  startDate: string,
  endDate: string,
  releaseIds: string[],
  summary: MicrosoftReportResult["summary"],
): string {
  const mainItems = items.filter((item) => item.windowsFamily);
  const otherItems = items.filter((item) => !item.windowsFamily);
  const clusters = summary.clusters.slice(0, 7).map((cluster) => `${cluster.name}(${cluster.count})`).join(", ") || "Sem CVEs";
  const to = process.env["MICROSOFT_REPORT_TO"]?.trim() || "Destinatários não configurados";
  const cc = process.env["MICROSOFT_REPORT_CC"]?.trim() || "Cópia não configurada";

  const clusterHtml = summary.clusters.length
    ? `<ul>${summary.clusters.map((cluster) => `<li style="margin-bottom:5px;"><strong>${escapeHtml(cluster.name)}:</strong> ${cluster.count} vulnerabilidade(s).</li>`).join("")}</ul>`
    : "<p>Nenhum cluster foi formado.</p>";

  return `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><title>Patch Tuesday Microsoft</title></head>
<body style="font-family:Arial,sans-serif;color:#333;line-height:1.5;font-size:14px;max-width:1100px;margin:0 auto;padding:16px;">
  <div style="background-color:#f8f9fa;padding:15px;border:1px solid #ddd;margin-bottom:20px;">
    <h3 style="margin-top:0;color:#0056b3;">📧 Envio do Relatório Patch Tuesday</h3>
    <p style="margin:5px 0;"><strong>Para:</strong> ${escapeHtml(to)}</p>
    <p style="margin:5px 0;"><strong>Cc:</strong> ${escapeHtml(cc)}</p>
    <p style="margin:5px 0;"><strong>Assunto:</strong> Relatório Microsoft Patch Tuesday (${escapeHtml(formatDatePt(startDate))} a ${escapeHtml(formatDatePt(endDate))}) | ${escapeHtml(clusters)}</p>
  </div>

  <p>Prezados,</p>
  <p>Solicito a avaliação e aplicação planejada das atualizações de segurança Microsoft referentes ao período de <strong>${escapeHtml(startDate)}</strong> a <strong>${escapeHtml(endDate)}</strong>.</p>

  <h2 style="color:#2c3e50;border-bottom:2px solid #2c3e50;padding-bottom:5px;">Microsoft Patch Tuesday</h2>
  <p style="font-size:12px;color:#666;">Documentos MSRC consultados: ${escapeHtml(releaseIds.join(", "))} · Emitido por: Kryptus SOC</p>

  <blockquote style="background-color:#eef2f5;border-left:5px solid #0078d4;padding:10px 15px;margin:0 0 20px 0;">
    Foram consolidadas <strong>${summary.total} CVE(s)</strong> nos documentos oficiais do Microsoft Security Response Center. A priorização deve considerar ativos afetados, exposição, criticidade e exploração conhecida.
  </blockquote>

  <h3 style="color:#2c3e50;">TOTAIS DO CICLO</h3>
  <table style="width:100%;border-collapse:collapse;text-align:center;margin-bottom:30px;"><tbody><tr>
    ${metricCell(summary.total, "Total de CVEs", "#2c3e50", "#f0f4f8")}
    ${metricCell(summary.critical, "Críticas", "#d32f2f", "#fbecec")}
    ${metricCell(summary.important, "Importantes", "#f57c00", "#fdf3e8")}
    ${metricCell(summary.exploited, "Exploração conhecida", "#cc0000", "#f9f9f9")}
    ${metricCell(summary.publiclyDisclosed, "Divulgadas publicamente", "#0056b3", "#eef5fb")}
  </tr></tbody></table>

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;">Resumo de Correlação</h3>
  ${clusterHtml}

  <div style="background-color:#eef5fb;border-left:5px solid #0078d4;padding:15px;margin:25px 0 20px;">
    <h3 style="color:#005a9e;margin-top:0;">🪟 Windows, Windows Server e Produtos Corporativos</h3>
    <p style="margin-bottom:10px;">Priorize controladores de domínio, servidores expostos, estações administrativas e produtos com exploração conhecida.</p>
  </div>
  ${renderMicrosoftTable(mainItems, "#0078d4", "Nenhuma CVE de Windows ou produtos corporativos foi identificada.")}

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;">Demais produtos Microsoft</h3>
  ${renderMicrosoftTable(otherItems, "#2c3e50", "Nenhuma CVE adicional foi identificada.")}

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;">Referências para Consulta</h3>
  <ul>
    <li><strong>Microsoft Security Update Guide:</strong> <a href="https://msrc.microsoft.com/update-guide/">https://msrc.microsoft.com/update-guide/</a></li>
    <li><strong>MSRC CVRF API:</strong> <a href="https://api.msrc.microsoft.com/cvrf/v3.0">https://api.msrc.microsoft.com/cvrf/v3.0</a></li>
    <li><strong>Microsoft Update Catalog:</strong> <a href="https://www.catalog.update.microsoft.com/">https://www.catalog.update.microsoft.com/</a></li>
    <li><strong>CISA KEV:</strong> <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">https://www.cisa.gov/known-exploited-vulnerabilities-catalog</a></li>
  </ul>
</body></html>`;
}

function metricCell(value: number, label: string, color: string, background: string): string {
  return `<td style="border:1px solid #ddd;padding:15px;background-color:${background};"><span style="font-size:28px;font-weight:bold;color:${color};">${value}</span><br><span style="font-size:12px;color:${color};font-weight:bold;">${escapeHtml(label)}</span></td>`;
}

function renderMicrosoftTable(items: MicrosoftReportItem[], headerColor: string, emptyText: string): string {
  const rows = items.length
    ? items.map((item) => {
        const productText = item.products.length ? item.products.slice(0, 8).join(", ") : "Consultar MSRC";
        const kbText = item.kbArticles.length ? item.kbArticles.slice(0, 5).join(", ") : "Consultar Security Update Guide";
        const firstUrl = item.patchUrls[0];
        return `<tr style="background-color:#f9f9f9;border-bottom:1px solid #eee;">
          <td style="padding:8px;border:1px solid #ddd;font-weight:bold;color:#0056b3;">${escapeHtml(item.cveId)}${item.exploited ? "<br><span style='font-size:10px;color:#cc0000;'>EXPLORAÇÃO CONHECIDA</span>" : ""}</td>
          <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(item.impact)}<br><span style="font-size:10px;color:#666;">${escapeHtml(truncate(item.title, 140))}</span></td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;">${escapeHtml(item.cvss)}</td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;color:${severityColor(item.severity)};font-weight:bold;">${escapeHtml(item.severity)}</td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;">${item.exploited ? "Sim" : "Não confirmada"}${item.publiclyDisclosed ? "<br><span style='font-size:10px;color:#0056b3;'>Divulgada publicamente</span>" : ""}</td>
          <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(productText)}</td>
          <td style="padding:8px;border:1px solid #ddd;">${firstUrl ? `<a href="${escapeHtml(firstUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(kbText)}</a>` : escapeHtml(kbText)}<br><span style="font-size:10px;color:#666;">Reinício: ${escapeHtml(item.restart)}</span></td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="7" style="text-align:center;padding:18px;border:1px solid #ddd;">${escapeHtml(emptyText)}</td></tr>`;

  return `<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:30px;">
    <thead><tr style="background-color:${headerColor};color:#fff;text-align:left;">
      <th style="padding:8px;border:1px solid #ddd;">CVE</th>
      <th style="padding:8px;border:1px solid #ddd;">Impacto / Título</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">CVSS</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">Severidade</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">Exploração</th>
      <th style="padding:8px;border:1px solid #ddd;">Produtos afetados</th>
      <th style="padding:8px;border:1px solid #ddd;">KB / Atualização</th>
    </tr></thead><tbody>${rows}</tbody>
  </table>`;
}
