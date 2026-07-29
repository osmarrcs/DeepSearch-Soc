import { fetchWithTimeout, getCisaKevFeed } from "./scanner";
import { logger } from "./logger";
import {
  addUtcDays,
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

const RED_HAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json";

interface RedHatPackageState {
  product_name?: string;
  package_name?: string;
  fix_state?: string;
  cpe?: string;
}

interface RedHatRawCve {
  CVE?: string;
  severity?: string;
  public_date?: string;
  bugzilla_description?: string;
  cvss3_score?: string | number;
  cvss3_scoring_vector?: string;
  CWE?: string;
  package_state?: RedHatPackageState[] | null;
  advisories?: string[] | string | null;
  resource_url?: string;
}

export interface RedHatReportItem {
  cveId: string;
  description: string;
  component: string;
  impact: string;
  cvss: string;
  severity: string;
  vector: string;
  cwe: string;
  affectedVersions: string[];
  advisories: string[];
  kernel: boolean;
  cisaKev: boolean;
  resourceUrl: string;
}

export interface RedHatReportResult {
  html: string;
  startDate: string;
  endDate: string;
  summary: {
    total: number;
    critical: number;
    important: number;
    cisaKev: number;
    clusters: Array<{ name: string; count: number }>;
  };
  items: RedHatReportItem[];
}

export async function generateRedHatReport(startDate: unknown, endDate: unknown): Promise<RedHatReportResult> {
  const range = parseDateRange(startDate, endDate, 120);
  const params = new URLSearchParams({
    after: range.startDate,
    // A API usa "before" como limite superior; +1 inclui o dia final escolhido.
    before: addUtcDays(range.endDate, 1),
    severity: "critical,important",
    per_page: "1000",
  });

  const response = await fetchWithTimeout(
    `${RED_HAT_CVE_URL}?${params}`,
    {
      headers: {
        Accept: "application/json",
        "User-Agent": "DeepSearch-SOC/12.0",
      },
    },
    30000,
  );

  if (!response.ok) {
    throw new Error(`Red Hat Security Data retornou HTTP ${response.status}.`);
  }

  const payload = (await response.json()) as unknown;
  const rawItems = Array.isArray(payload)
    ? (payload as RedHatRawCve[])
    : arrayValue<RedHatRawCve>((payload as Record<string, unknown> | null)?.["data"]);
  const kev = await getCisaKevFeed();
  const kevIds = new Set(kev.map((item) => item.cveID).filter(Boolean));

  const items = rawItems
    .map((item) => normalizeRedHatItem(item, kevIds))
    .filter((item) => item.cveId !== "N/A")
    .sort((a, b) => {
      const severityOrder = severityRank(b.severity) - severityRank(a.severity);
      if (severityOrder !== 0) return severityOrder;
      return (numberValue(b.cvss) ?? 0) - (numberValue(a.cvss) ?? 0);
    });

  const clusters = buildClusters(items);
  const summary = {
    total: items.length,
    critical: items.filter((item) => item.severity === "Crítica").length,
    important: items.filter((item) => item.severity === "Importante").length,
    cisaKev: items.filter((item) => item.cisaKev).length,
    clusters,
  };

  return {
    html: renderRedHatHtml(items, range.startDate, range.endDate, summary),
    startDate: range.startDate,
    endDate: range.endDate,
    summary,
    items,
  };
}

function normalizeRedHatItem(raw: RedHatRawCve, kevIds: Set<string | undefined>): RedHatReportItem {
  const cveId = safeText(raw.CVE, "N/A").toUpperCase();
  const description = safeText(raw.bugzilla_description, "Sem descrição disponível.");
  const [componentPart, impactPart] = splitDescription(description);
  const packageStates = arrayValue<RedHatPackageState>(raw.package_state);
  const packageNames = uniqueStrings(packageStates.map((state) => state.package_name));
  const component = packageNames[0] || componentPart || "Outros";
  const normalizedSeverity = safeText(raw.severity, "important").toLowerCase();
  const severity = normalizedSeverity === "critical" ? "Crítica" : "Importante";
  const affectedVersions = uniqueStrings(
    packageStates
      .map((state) => state.product_name)
      .filter((product) => product?.includes("Enterprise Linux"))
      .map((product) => product?.replace("Red Hat Enterprise Linux ", "RHEL ")),
  );

  const advisories = Array.isArray(raw.advisories)
    ? uniqueStrings(raw.advisories)
    : typeof raw.advisories === "string"
      ? uniqueStrings(raw.advisories.split(/[\s,]+/))
      : [];

  const componentKey = `${component} ${componentPart}`.toLowerCase();
  return {
    cveId,
    description,
    component,
    impact: impactPart || description,
    cvss: safeText(raw.cvss3_score, "N/A"),
    severity,
    vector: safeText(raw.cvss3_scoring_vector, "N/A"),
    cwe: safeText(raw.CWE, "-----"),
    affectedVersions,
    advisories,
    kernel: componentKey.includes("kernel"),
    cisaKev: kevIds.has(cveId),
    resourceUrl: normalizeRedHatUrl(raw.resource_url, cveId),
  };
}

function normalizeRedHatUrl(value: unknown, cveId: string): string {
  const fallback = `https://access.redhat.com/security/cve/${encodeURIComponent(cveId)}`;
  const text = safeText(value, fallback);
  if (/^https?:\/\//i.test(text)) return text;
  if (text.startsWith("/")) return `https://access.redhat.com${text}`;
  return fallback;
}

function splitDescription(description: string): [string, string] {
  const separator = description.indexOf(":");
  if (separator < 0) return ["Outros", description];
  return [description.slice(0, separator).trim(), description.slice(separator + 1).trim()];
}

function buildClusters(items: RedHatReportItem[]): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const item of items) {
    const name = item.kernel ? "Kernel" : normalizeComponent(item.component);
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function normalizeComponent(value: string): string {
  const clean = value.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
  if (!clean || clean.toLowerCase() === "outros") return "Outros";
  return clean.charAt(0).toUpperCase() + clean.slice(1);
}

function severityRank(value: string): number {
  return value === "Crítica" ? 2 : 1;
}

function renderRedHatHtml(
  items: RedHatReportItem[],
  startDate: string,
  endDate: string,
  summary: RedHatReportResult["summary"],
): string {
  const kernelItems = items.filter((item) => item.kernel);
  const otherItems = items.filter((item) => !item.kernel);
  const clusterSubject = summary.clusters.slice(0, 6).map((cluster) => `${cluster.name}(${cluster.count})`).join(", ") || "Sem CVEs";
  const suffix = summary.clusters.length > 6 ? ", Outros" : "";

  const jFpeTo = process.env["REDHAT_JFPE_TO"]?.trim() || "Destinatários JFPE não configurados";
  const trfTo = process.env["REDHAT_TRF5_TO"]?.trim() || "Destinatários TRF5 não configurados";
  const defaultCc = process.env["REDHAT_REPORT_CC"]?.trim() || "Cópia não configurada";

  const clusterSummary = summary.clusters.length
    ? `<ul>${summary.clusters.map((cluster) => {
        const explanation = cluster.name === "Kernel"
          ? "falha(s) afetando o núcleo do sistema, incluindo riscos como elevação de privilégio, corrupção de memória e indisponibilidade"
          : `vulnerabilidade(s) relacionada(s) ao componente ${cluster.name}`;
        return `<li style="margin-bottom:5px;"><strong>Cluster ${escapeHtml(cluster.name)}:</strong> ${cluster.count} ${escapeHtml(explanation)}.</li>`;
      }).join("")}</ul>`
    : "<p>Nenhum cluster foi formado no período.</p>";

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><title>Relatório CVE Red Hat</title></head>
<body style="font-family:Arial,sans-serif;color:#333;line-height:1.5;font-size:14px;max-width:1000px;margin:0 auto;padding:16px;">
  <div style="background-color:#f8f9fa;padding:15px;border:1px solid #ddd;margin-bottom:20px;">
    <h3 style="margin-top:0;color:#0056b3;">📧 OPÇÃO 1: Envio para JFPE</h3>
    <p style="margin:5px 0;"><strong>Para:</strong> ${escapeHtml(jFpeTo)}</p>
    <p style="margin:5px 0;"><strong>Cc:</strong> ${escapeHtml(defaultCc)}</p>
    <p style="margin:5px 0;"><strong>Assunto:</strong> JFPE - Relatório CVE Red Hat (${escapeHtml(formatDatePt(startDate))} a ${escapeHtml(formatDatePt(endDate))}) | Clusters: ${escapeHtml(clusterSubject + suffix)}</p>
    <hr style="border:0;border-top:1px solid #ccc;margin:15px 0;">
    <h3 style="margin-top:0;color:#0056b3;">📧 OPÇÃO 2: Envio para TRF5</h3>
    <p style="margin:5px 0;"><strong>Para:</strong> ${escapeHtml(trfTo)}</p>
    <p style="margin:5px 0;"><strong>Cc:</strong> ${escapeHtml(defaultCc)}</p>
    <p style="margin:5px 0;"><strong>Assunto:</strong> TRF5 - Relatório CVE Red Hat (${escapeHtml(formatDatePt(startDate))} a ${escapeHtml(formatDatePt(endDate))}) | Clusters: ${escapeHtml(clusterSubject + suffix)}</p>
  </div>

  <p>Prezados,</p>
  <p>Solicito a avaliação técnica preventiva nos ambientes devido às vulnerabilidades (CVEs) reportadas pela Red Hat entre <strong>${escapeHtml(startDate)}</strong> e <strong>${escapeHtml(endDate)}</strong>.</p>

  <h2 style="color:#2c3e50;border-bottom:2px solid #2c3e50;padding-bottom:5px;">Boletins de CVE Red Hat</h2>
  <p style="font-size:12px;color:#666;">Emitido por: Kryptus SOC</p>

  <blockquote style="background-color:#eef2f5;border-left:5px solid #3498db;padding:10px 15px;margin:0 0 20px 0;">
    A Red Hat publicou <strong>${summary.total} CVE(s)</strong> de severidade Crítica e Importante no período filtrado. A análise tem caráter preventivo.
  </blockquote>

  <h3 style="color:#2c3e50;">TOTAIS POR SEVERIDADE</h3>
  <table style="width:100%;border-collapse:collapse;text-align:center;margin-bottom:30px;">
    <tbody><tr>
      ${metricCell(summary.total, "Total de CVEs", "#2c3e50", "#f0f4f8")}
      ${metricCell(summary.critical, "Críticas", "#d32f2f", "#fbecec")}
      ${metricCell(summary.important, "Importantes", "#f57c00", "#fdf3e8")}
      ${metricCell(summary.cisaKev, "CISA KEV", "#cc0000", "#f9f9f9")}
    </tr></tbody>
  </table>

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;">Resumo de Correlação</h3>
  <p>Foram identificados os seguintes clusters no lote de ${summary.total} falhas de segurança:</p>
  ${clusterSummary}

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;margin-top:30px;">Destaques de Infraestrutura, Automação, IA e Redes</h3>
  ${renderTable(otherItems, "#2c3e50", "Nenhuma CVE encontrada para esta categoria no período.")}

  <div style="background-color:#fdf2f2;border-left:5px solid #cc0000;padding:15px;margin:25px 0 20px;">
    <h3 style="color:#cc0000;margin-top:0;">🔴 Linux Kernel — Elevação de Privilégio, Corrupção de Memória e DoS</h3>
    <p style="margin-bottom:10px;">Destaques para falhas reportadas no núcleo do sistema operacional. A priorização final deve considerar exposição, versão implantada, exploração conhecida e controles compensatórios.</p>
  </div>
  ${renderTable(kernelItems, "#cc0000", "Nenhuma CVE de Kernel encontrada no período.")}

  <h3 style="color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:5px;">Referências para Consulta</h3>
  <ul>
    <li><strong>Red Hat Security Data:</strong> <a href="https://access.redhat.com/security/data">https://access.redhat.com/security/data</a></li>
    <li><strong>Red Hat CVE Database:</strong> <a href="https://access.redhat.com/security/security-updates/cve">https://access.redhat.com/security/security-updates/cve</a></li>
    <li><strong>Red Hat Security Advisories:</strong> <a href="https://access.redhat.com/errata/">https://access.redhat.com/errata/</a></li>
    <li><strong>CISA KEV:</strong> <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">https://www.cisa.gov/known-exploited-vulnerabilities-catalog</a></li>
  </ul>
</body></html>`;
}

function metricCell(value: number, label: string, color: string, background: string): string {
  return `<td style="border:1px solid #ddd;padding:15px;background-color:${background};"><span style="font-size:28px;font-weight:bold;color:${color};">${value}</span><br><span style="font-size:12px;color:${color};font-weight:bold;">${escapeHtml(label)}</span></td>`;
}

function renderTable(items: RedHatReportItem[], headerColor: string, emptyText: string): string {
  const rows = items.length
    ? items.map((item) => {
        const versions = item.affectedVersions.length ? item.affectedVersions.slice(0, 5).join(", ") : "Consultar RHSA";
        const advisoryText = item.advisories.length ? `<br><span style="font-size:10px;color:#666;">${escapeHtml(item.advisories.slice(0, 3).join(", "))}</span>` : "";
        return `<tr style="background-color:#f9f9f9;border-bottom:1px solid #eee;">
          <td style="padding:8px;border:1px solid #ddd;font-weight:bold;color:${item.kernel ? "#cc0000" : "#0056b3"};"><a href="${escapeHtml(item.resourceUrl)}" target="_blank" rel="noopener noreferrer" style="color:inherit;">${escapeHtml(item.cveId)}</a>${item.cisaKev ? "<br><span style='font-size:10px;color:#cc0000;'>CISA KEV</span>" : ""}</td>
          <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(item.component)} / ${escapeHtml(truncate(item.impact, 120))}${advisoryText}</td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;">${escapeHtml(item.cvss)}</td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;color:${severityColor(item.severity)};font-weight:bold;">${escapeHtml(item.severity)}</td>
          <td style="padding:8px;border:1px solid #ddd;word-break:break-word;">${escapeHtml(item.vector)}</td>
          <td style="padding:8px;border:1px solid #ddd;text-align:center;">${escapeHtml(item.cwe)}</td>
          <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(versions)}</td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="7" style="text-align:center;padding:18px;border:1px solid #ddd;">${escapeHtml(emptyText)}</td></tr>`;

  return `<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:30px;">
    <thead><tr style="background-color:${headerColor};color:#fff;text-align:left;">
      <th style="padding:8px;border:1px solid #ddd;">CVE</th>
      <th style="padding:8px;border:1px solid #ddd;">Componente / Impacto</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">CVSS</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">Severidade</th>
      <th style="padding:8px;border:1px solid #ddd;">Vetor CVSS</th>
      <th style="padding:8px;border:1px solid #ddd;text-align:center;">CWE</th>
      <th style="padding:8px;border:1px solid #ddd;">Versões Afetadas</th>
    </tr></thead><tbody>${rows}</tbody>
  </table>`;
}

// Mantém um log útil sem incluir conteúdo do relatório ou destinatários.
export function logRedHatReport(result: RedHatReportResult): void {
  logger.info({
    period: `${result.startDate}..${result.endDate}`,
    total: result.summary.total,
    critical: result.summary.critical,
    cisaKev: result.summary.cisaKev,
  }, "Red Hat report generated");
}
