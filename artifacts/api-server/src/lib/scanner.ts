import { logger } from "./logger";

export interface CveResult {
  id: string;
  tech: string;
  desc: string;
  solution: string;
  cvss: string;
  source: string;
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 12000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function searchCisaKev(tech: string): Promise<CveResult[]> {
  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url);
    if (!resp.ok) return results;
    const data = await resp.json() as { vulnerabilities?: Record<string, string>[] };
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    for (const vuln of data.vulnerabilities ?? []) {
      const dateAdded = new Date(vuln["dateAdded"] ?? "");
      if (isNaN(dateAdded.getTime()) || dateAdded < thirtyDaysAgo) continue;
      const vendor = (vuln["vendorProject"] ?? "").toLowerCase();
      const product = (vuln["product"] ?? "").toLowerCase();
      if (!vendor.includes(tech.toLowerCase()) && !product.includes(tech.toLowerCase())) continue;
      results.push({
        id: vuln["cveID"] ?? `CISA-${Date.now()}`,
        tech,
        desc: vuln["shortDescription"] ?? "Sem descrição disponível.",
        solution: vuln["requiredAction"] ?? "Aplicar correção conforme orientação do fabricante.",
        cvss: "N/D (Exploração Ativa)",
        source: "CISA KEV",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "CISA KEV fetch failed");
  }
  return results;
}

export async function searchOsvDev(tech: string): Promise<CveResult[]> {
  const url = "https://api.osv.dev/v1/query";
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { name: tech.toLowerCase() } }),
    });
    if (!resp.ok) return results;
    const data = await resp.json() as { vulns?: Record<string, string>[] };
    for (const vuln of (data.vulns ?? []).slice(0, 2)) {
      results.push({
        id: vuln["id"] ?? "OSV-VULN",
        tech,
        desc: vuln["details"] ?? vuln["summary"] ?? "Detalhes técnicos fornecidos na base OSV.",
        solution: "Atualizar biblioteca/pacote afetado no repositório.",
        cvss: "N/D",
        source: "OSV.dev (Open Source)",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "OSV.dev fetch failed");
  }
  return results;
}

export async function searchCircl(tech: string): Promise<CveResult[]> {
  const url = `https://cve.circl.lu/api/search/${encodeURIComponent(tech.toLowerCase())}`;
  const results: CveResult[] = [];
  try {
    const resp = await fetchWithTimeout(url);
    if (!resp.ok) return results;
    const data = await resp.json() as { data?: Record<string, unknown>[] };
    for (const vuln of (data.data ?? []).slice(0, 2)) {
      results.push({
        id: String(vuln["id"] ?? ""),
        tech,
        desc: String(vuln["summary"] ?? "Sem descrição disponível."),
        solution: "Verificar boletins do fabricante.",
        cvss: String(vuln["cvss"] ?? "N/D"),
        source: "CIRCL CVE Search",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "CIRCL fetch failed");
  }
  return results;
}

export async function searchNvd(tech: string): Promise<CveResult[]> {
  const results: CveResult[] = [];
  try {
    const hoje = new Date();
    const inicio = new Date();
    inicio.setDate(inicio.getDate() - 7);
    const params = new URLSearchParams({
      pubStartDate: inicio.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      pubEndDate: hoje.toISOString().replace(/\.\d{3}Z$/, ".000Z"),
      keywordSearch: tech,
      resultsPerPage: "2",
    });
    // NVD rate-limit: 6s delay between requests if no API key
    await new Promise((r) => setTimeout(r, 6000));
    const resp = await fetchWithTimeout(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, {}, 20000);
    if (!resp.ok) return results;
    const data = await resp.json() as { vulnerabilities?: { cve: Record<string, unknown> }[] };
    for (const item of data.vulnerabilities ?? []) {
      const cve = item.cve;
      const metrics = cve["metrics"] as Record<string, unknown> | undefined;
      let cvss = "N/D";
      if (metrics && metrics["cvssMetricV31"]) {
        const m = (metrics["cvssMetricV31"] as { cvssData?: { baseScore?: number } }[])[0];
        if (m?.cvssData?.baseScore != null) cvss = String(m.cvssData.baseScore);
      } else if (metrics && metrics["cvssMetricV30"]) {
        const m = (metrics["cvssMetricV30"] as { cvssData?: { baseScore?: number } }[])[0];
        if (m?.cvssData?.baseScore != null) cvss = String(m.cvssData.baseScore);
      }
      const descriptions = cve["descriptions"] as { lang: string; value: string }[] | undefined;
      const desc = descriptions?.find((d) => d.lang === "en")?.value ?? "Sem descrição disponível.";
      results.push({
        id: String(cve["id"] ?? ""),
        tech,
        desc,
        solution: "Aplicar atualizações de segurança fornecidas pelo fabricante ou rotacionar credenciais afetadas.",
        cvss,
        source: "NVD / NIST",
      });
    }
  } catch (err) {
    logger.warn({ err, tech }, "NVD fetch failed");
  }
  return results;
}

export function generateTenableReport(vuln: {
  cveId: string;
  tech: string;
  source: string;
  description: string;
  solution: string;
  cvss: string;
}): string {
  const cvssFloat = parseFloat(vuln.cvss);
  let severity = "Informativo";
  let severityColor = "#2196f3";
  if (vuln.cvss === "N/D (Exploração Ativa)" || cvssFloat >= 9.0) {
    severity = "Crítico";
    severityColor = "#e53935";
  } else if (cvssFloat >= 7.0) {
    severity = "Alto";
    severityColor = "#f4511e";
  } else if (cvssFloat >= 4.0) {
    severity = "Médio";
    severityColor = "#f9a825";
  }

  return `
<div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.5; max-width: 900px; margin: 20px auto; border: 1px solid #e0e0e0; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background-color: #fff;">
  <h1 style="font-size: 22px; color: #1a1a1a; border-bottom: 1px solid #eaeaea; padding-bottom: 15px; margin-top: 0;">
    Relatório de Vulnerabilidade — Tenable One
  </h1>

  <div style="background-color: #eaffea; border-left: 4px solid #00d282; padding: 12px 15px; margin: 20px 0; font-size: 13px;">
    <strong>Fonte:</strong> ${vuln.source} &mdash; Este relatório é gerado automaticamente a partir de bases públicas de inteligência de ameaças.
  </div>

  <div style="margin: 30px 0; padding: 20px; border: 1px solid #dcdcdc; border-radius: 4px; background-color: #fbfbfb;">
    <h2 style="font-size: 18px; margin-top: 0; color: #005a8c;">
      ${vuln.cveId} — ${vuln.tech}
    </h2>
    <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
      <tr>
        <td style="padding: 8px 0; width: 200px; color: #555; font-weight: bold;">Identificador:</td>
        <td style="padding: 8px 0;">${vuln.cveId}</td>
      </tr>
      <tr style="background-color: #f9f9f9;">
        <td style="padding: 8px; color: #555; font-weight: bold;">Tecnologia Afetada:</td>
        <td style="padding: 8px;">${vuln.tech}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #555; font-weight: bold;">Fonte de Inteligência:</td>
        <td style="padding: 8px 0;">${vuln.source}</td>
      </tr>
      <tr style="background-color: #f9f9f9;">
        <td style="padding: 8px; color: #555; font-weight: bold;">Base Score CVSSv3:</td>
        <td style="padding: 8px;">
          <span style="background-color: ${severityColor}; color: #fff; padding: 2px 10px; border-radius: 3px; font-weight: bold; font-size: 13px;">
            ${vuln.cvss} — ${severity}
          </span>
        </td>
      </tr>
    </table>
  </div>

  <div style="margin: 20px 0;">
    <h3 style="font-size: 15px; color: #1a2228; margin-bottom: 8px;">Descrição</h3>
    <p style="font-size: 14px; background-color: #f4f8fd; border-left: 4px solid #007bc1; padding: 12px 15px; margin: 0;">${vuln.description}</p>
  </div>

  <div style="margin: 20px 0;">
    <h3 style="font-size: 15px; color: #1a2228; margin-bottom: 8px;">Mitigação Recomendada</h3>
    <p style="font-size: 14px; background-color: #f9fff9; border-left: 4px solid #00d282; padding: 12px 15px; margin: 0;">${vuln.solution}</p>
  </div>

  <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 30px 0;">

  <p style="font-size: 12px; color: #888;">
    Relatório gerado em ${new Date().toLocaleString("pt-BR")} via Deep Research de Vulnerabilidades.
    Para mais informações, consulte os boletins oficiais do fabricante e as bases CVE/NVD.
  </p>
</div>
`.trim();
}
