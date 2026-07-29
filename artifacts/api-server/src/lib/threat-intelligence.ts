import { fetchWithTimeout, getCisaKevFeed, waitForNvdSlot } from "./scanner";
import { logger } from "./logger";

const NVD_API_KEY = process.env["NVD_API_KEY"]?.trim() ?? "";
const GEMINI_API_KEY = process.env["GEMINI_API_KEY"]?.trim() ?? "";
const GEMINI_MODEL = process.env["GEMINI_MODEL"]?.trim() || "gemini-3.6-flash";
const GEMINI_FALLBACK_MODEL = process.env["GEMINI_FALLBACK_MODEL"]?.trim() || "gemini-3.5-flash-lite";

const REPORT_CACHE_TTL_MS = 30 * 60 * 1000;
const MAX_REFERENCE_DOCUMENTS = 4;
const MAX_REFERENCE_TEXT = 6000;
const MAX_PROMPT_CONTEXT = 48000;

interface VulnerabilitySeed {
  cveId: string;
  tech: string;
  source: string;
  description: string;
  solution: string;
  cvss: string;
}

export interface ThreatAnalysis {
  tipo_evento: string;
  resumo_executivo: string;
  impacto_tecnico: string;
  produtos_afetados: string;
  versoes_afetadas: string;
  vetor_ataque: string;
  mecanica_exploracao: string;
  exploracao_ativa: string;
  patch_disponivel: string;
  mitigacoes_temporarias: string;
  deteccao_soc: string;
  indicadores_comprometimento: string;
  prioridade_recomendada: string;
  recomendacao: string;
  fontes_utilizadas: Array<{
    nome: string;
    url: string;
    contribuicao: string;
  }>;
  lacunas_de_informacao: string[];
  nivel_confianca: string;
  justificativa_confianca: string;
}

export interface ProfessionalReport {
  html: string;
  analysis: ThreatAnalysis;
  modelUsed: string | null;
  cacheHit: boolean;
}

interface NvdReference {
  url: string;
  source?: string;
  tags: string[];
}

interface NvdRecord {
  id: string;
  published?: string;
  lastModified?: string;
  status?: string;
  description: string;
  cvss: {
    score: number | null;
    severity: string | null;
    vector: string | null;
    version: string | null;
    exploitabilityScore: number | null;
    impactScore: number | null;
  };
  cwes: string[];
  affectedConfigurations: Array<{
    criteria?: string;
    versionStartIncluding?: string;
    versionStartExcluding?: string;
    versionEndIncluding?: string;
    versionEndExcluding?: string;
  }>;
  references: NvdReference[];
  vendorComments: unknown[];
}

interface CveRecord {
  available: boolean;
  title?: string;
  description?: string;
  affected?: unknown[];
  problemTypes?: unknown[];
  metrics?: unknown[];
  references?: Array<{ url?: string; name?: string; tags?: string[] }>;
  providerMetadata?: unknown;
  error?: string;
}

interface EpssRecord {
  available: boolean;
  probability?: number;
  percentile?: number;
  date?: string;
  error?: string;
}

interface ReferenceDocument {
  url: string;
  source: string;
  tags: string[];
  title: string;
  collected: boolean;
  text: string;
  error?: string;
}

interface IntelligencePackage {
  cveId: string;
  technology: string;
  collectedAt: string;
  seed: VulnerabilitySeed;
  nvd: NvdRecord | null;
  cveProgram: CveRecord;
  cisaKev: Record<string, unknown> | null;
  epss: EpssRecord;
  referenceDocuments: ReferenceDocument[];
}

const reportCache = new Map<string, { expiresAt: number; value: ProfessionalReport }>();

export function getIntelligenceConfig() {
  return {
    geminiApiKeyConfigured: Boolean(GEMINI_API_KEY),
    geminiModel: GEMINI_MODEL,
    geminiFallbackModel: GEMINI_FALLBACK_MODEL,
    reportCacheMinutes: REPORT_CACHE_TTL_MS / 60000,
  };
}

export async function generateProfessionalReport(seed: VulnerabilitySeed): Promise<ProfessionalReport> {
  const key = `${seed.cveId}:${seed.tech}`.toUpperCase();
  const cached = reportCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return { ...cached.value, cacheHit: true };
  }

  const intelligence = await buildIntelligencePackage(seed);
  const { analysis, modelUsed } = await analyzeWithGemini(intelligence);
  const html = renderColabStyleReport(intelligence, analysis);
  const value: ProfessionalReport = { html, analysis, modelUsed, cacheHit: false };
  reportCache.set(key, { expiresAt: Date.now() + REPORT_CACHE_TTL_MS, value });
  return value;
}

async function buildIntelligencePackage(seed: VulnerabilitySeed): Promise<IntelligencePackage> {
  const [nvd, cveProgram, cisaKev, epss] = await Promise.all([
    fetchNvdRecord(seed.cveId),
    fetchCveProgramRecord(seed.cveId),
    findCisaKev(seed.cveId),
    fetchEpss(seed.cveId),
  ]);

  const references = mergeReferences(nvd?.references ?? [], cveProgram.references ?? []);
  const referenceDocuments = await Promise.all(
    references.slice(0, MAX_REFERENCE_DOCUMENTS).map(fetchReferenceDocument),
  );

  return {
    cveId: seed.cveId,
    technology: seed.tech,
    collectedAt: new Date().toISOString(),
    seed,
    nvd,
    cveProgram,
    cisaKev,
    epss,
    referenceDocuments,
  };
}

async function fetchNvdRecord(cveId: string): Promise<NvdRecord | null> {
  try {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "DeepSearch-SOC/11.0",
    };
    if (NVD_API_KEY) headers.apiKey = NVD_API_KEY;

    const params = new URLSearchParams({ cveId });
    await waitForNvdSlot();
    const response = await fetchWithTimeout(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`,
      { headers },
      25000,
    );
    if (!response.ok) throw new Error(`NVD HTTP ${response.status}`);

    const payload = (await response.json()) as {
      vulnerabilities?: Array<{ cve?: Record<string, unknown> }>;
    };
    const cve = payload.vulnerabilities?.[0]?.cve;
    if (!cve) return null;

    return {
      id: String(cve["id"] ?? cveId),
      published: stringOrUndefined(cve["published"]),
      lastModified: stringOrUndefined(cve["lastModified"]),
      status: stringOrUndefined(cve["vulnStatus"]),
      description: chooseDescription(cve["descriptions"]),
      cvss: extractCvss(cve["metrics"]),
      cwes: extractCwes(cve["weaknesses"]),
      affectedConfigurations: extractConfigurations(cve["configurations"]),
      references: extractNvdReferences(cve["references"]),
      vendorComments: Array.isArray(cve["vendorComments"]) ? cve["vendorComments"] : [],
    };
  } catch (error) {
    logger.warn({ error, cveId }, "NVD detail fetch failed");
    return null;
  }
}

async function fetchCveProgramRecord(cveId: string): Promise<CveRecord> {
  try {
    const response = await fetchWithTimeout(
      `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`,
      { headers: { Accept: "application/json" } },
      18000,
    );
    if (!response.ok) throw new Error(`CVE Program HTTP ${response.status}`);

    const payload = (await response.json()) as Record<string, unknown>;
    const containers = payload["containers"] as Record<string, unknown> | undefined;
    const cna = containers?.["cna"] as Record<string, unknown> | undefined;
    if (!cna) return { available: false, error: "Registro CNA ausente" };

    return {
      available: true,
      title: stringOrUndefined(cna["title"]),
      description: chooseDescription(cna["descriptions"]),
      affected: Array.isArray(cna["affected"]) ? cna["affected"] : [],
      problemTypes: Array.isArray(cna["problemTypes"]) ? cna["problemTypes"] : [],
      metrics: Array.isArray(cna["metrics"]) ? cna["metrics"] : [],
      references: Array.isArray(cna["references"])
        ? (cna["references"] as Array<{ url?: string; name?: string; tags?: string[] }>)
        : [],
      providerMetadata: cna["providerMetadata"],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Erro ao consultar CVE Program";
    logger.warn({ error, cveId }, "CVE Program fetch failed");
    return { available: false, error: message };
  }
}

async function findCisaKev(cveId: string): Promise<Record<string, unknown> | null> {
  const feed = await getCisaKevFeed();
  const item = feed.find((entry) => entry.cveID === cveId);
  return item ? { ...item } : null;
}

async function fetchEpss(cveId: string): Promise<EpssRecord> {
  try {
    const response = await fetchWithTimeout(
      `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`,
      { headers: { Accept: "application/json" } },
      10000,
    );
    if (!response.ok) throw new Error(`EPSS HTTP ${response.status}`);

    const payload = (await response.json()) as {
      data?: Array<{ epss?: string; percentile?: string; date?: string }>;
    };
    const item = payload.data?.[0];
    if (!item) return { available: false };

    return {
      available: true,
      probability: Number(item.epss ?? 0),
      percentile: Number(item.percentile ?? 0),
      date: item.date,
    };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : "Erro EPSS",
    };
  }
}

async function fetchReferenceDocument(reference: NvdReference): Promise<ReferenceDocument> {
  const normalizedReference = {
    ...reference,
    source: reference.source || safeHostname(reference.url) || "Referência técnica",
  };

  if (!isSafePublicUrl(reference.url)) {
    return {
      ...normalizedReference,
      title: "",
      collected: false,
      text: "",
      error: "URL não elegível para coleta automática",
    };
  }

  try {
    const response = await fetchWithTimeout(
      reference.url,
      {
        headers: {
          Accept: "text/html,application/json,text/plain;q=0.9,*/*;q=0.5",
          "User-Agent": "DeepSearch-SOC/11.0",
        },
        redirect: "follow",
      },
      9000,
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (contentType.includes("pdf") || reference.url.toLowerCase().endsWith(".pdf")) {
      return {
        ...normalizedReference,
        title: "Documento PDF",
        collected: false,
        text: "",
        error: "PDF mantido somente como referência",
      };
    }

    const raw = await response.text();
    const title = extractHtmlTitle(raw);
    const text = contentType.includes("json")
      ? normalizeWhitespace(raw)
      : stripHtml(raw);

    return {
      ...normalizedReference,
      title,
      collected: true,
      text: text.slice(0, MAX_REFERENCE_TEXT),
    };
  } catch (error) {
    return {
      ...normalizedReference,
      title: "",
      collected: false,
      text: "",
      error: error instanceof Error ? error.message : "Falha de coleta",
    };
  }
}

async function analyzeWithGemini(
  intelligence: IntelligencePackage,
): Promise<{ analysis: ThreatAnalysis; modelUsed: string | null }> {
  if (!GEMINI_API_KEY) {
    return { analysis: deterministicFallback(intelligence), modelUsed: null };
  }

  const context = JSON.stringify(
    {
      cve_id: intelligence.cveId,
      tecnologia: intelligence.technology,
      nvd: intelligence.nvd,
      cve_program_mitre: intelligence.cveProgram,
      cisa_kev: intelligence.cisaKev,
      epss: intelligence.epss,
      avisos_e_referencias: intelligence.referenceDocuments,
      dados_originais_da_varredura: intelligence.seed,
    },
    null,
    2,
  ).slice(0, MAX_PROMPT_CONTEXT);

  const prompt = `
Você é um analista sênior de Threat Intelligence e Vulnerability Management.

OBJETIVO
Correlacione as evidências abaixo e produza uma análise executiva técnica,
concisa, objetiva e totalmente em português do Brasil. Não faça somente uma
tradução ou um resumo da descrição da NVD.

REGRAS OBRIGATÓRIAS
1. Cruze NVD, CVE Program/MITRE, CISA KEV, EPSS, CVSS, CWE, CPE, avisos do fabricante, patches e notas de versão.
2. Priorize dados do fabricante ou da CNA quando estiverem disponíveis.
3. CISA KEV confirma exploração conhecida somente quando houver um registro correspondente.
4. EPSS é probabilidade estimada de exploração nos próximos 30 dias; não é confirmação de ataque e não substitui análise de risco.
5. Não invente versões, patches, IOCs, técnicas ATT&CK, exploits ou datas.
6. Identifique conclusões inferidas como "Inferência técnica".
7. Quando não houver confirmação, use "Não confirmado nas fontes consultadas".
8. Não gere payloads, código de exploit ou instruções ofensivas.
9. Nos campos de texto, não use Markdown, asteriscos ou crases.
10. Em fontes_utilizadas, use somente URLs presentes nos dados fornecidos.

DADOS CONSOLIDADOS
${context}

Retorne somente JSON válido com esta estrutura:
{
  "tipo_evento": "",
  "resumo_executivo": "",
  "impacto_tecnico": "",
  "produtos_afetados": "",
  "versoes_afetadas": "",
  "vetor_ataque": "",
  "mecanica_exploracao": "",
  "exploracao_ativa": "",
  "patch_disponivel": "",
  "mitigacoes_temporarias": "",
  "deteccao_soc": "",
  "indicadores_comprometimento": "",
  "prioridade_recomendada": "",
  "recomendacao": "",
  "fontes_utilizadas": [
    {"nome": "", "url": "", "contribuicao": ""}
  ],
  "lacunas_de_informacao": [],
  "nivel_confianca": "",
  "justificativa_confianca": ""
}`;

  const models = Array.from(new Set([GEMINI_MODEL, GEMINI_FALLBACK_MODEL].filter(Boolean)));
  const errors: string[] = [];

  for (const model of models) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
      const response = await fetchWithTimeout(
        endpoint,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ role: "user", parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: 0.1,
              maxOutputTokens: 5000,
              responseMimeType: "application/json",
            },
          }),
        },
        60000,
      );

      if (!response.ok) {
        const body = (await response.text()).slice(0, 1000);
        if (response.status === 404) {
          errors.push(`${model}: ${body}`);
          continue;
        }
        throw new Error(`Gemini HTTP ${response.status}: ${body}`);
      }

      const payload = (await response.json()) as {
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      };
      const text = payload.candidates?.[0]?.content?.parts?.map((part) => part.text ?? "").join("").trim();
      if (!text) throw new Error("Gemini não retornou conteúdo");

      const parsed = JSON.parse(stripJsonFence(text)) as Partial<ThreatAnalysis>;
      return { analysis: normalizeAnalysis(parsed, intelligence), modelUsed: model };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Erro Gemini";
      errors.push(`${model}: ${message}`);
      logger.warn({ error, model, cveId: intelligence.cveId }, "Gemini analysis failed");
    }
  }

  logger.warn({ errors, cveId: intelligence.cveId }, "Using deterministic report fallback");
  return { analysis: deterministicFallback(intelligence), modelUsed: null };
}

function normalizeAnalysis(
  value: Partial<ThreatAnalysis>,
  intelligence: IntelligencePackage,
): ThreatAnalysis {
  const fallback = deterministicFallback(intelligence);
  return {
    tipo_evento: cleanText(value.tipo_evento) || fallback.tipo_evento,
    resumo_executivo: cleanText(value.resumo_executivo) || fallback.resumo_executivo,
    impacto_tecnico: cleanText(value.impacto_tecnico) || fallback.impacto_tecnico,
    produtos_afetados: cleanText(value.produtos_afetados) || fallback.produtos_afetados,
    versoes_afetadas: cleanText(value.versoes_afetadas) || fallback.versoes_afetadas,
    vetor_ataque: cleanText(value.vetor_ataque) || fallback.vetor_ataque,
    mecanica_exploracao: cleanText(value.mecanica_exploracao) || fallback.mecanica_exploracao,
    exploracao_ativa: cleanText(value.exploracao_ativa) || fallback.exploracao_ativa,
    patch_disponivel: cleanText(value.patch_disponivel) || fallback.patch_disponivel,
    mitigacoes_temporarias: cleanText(value.mitigacoes_temporarias) || fallback.mitigacoes_temporarias,
    deteccao_soc: cleanText(value.deteccao_soc) || fallback.deteccao_soc,
    indicadores_comprometimento: cleanText(value.indicadores_comprometimento) || fallback.indicadores_comprometimento,
    prioridade_recomendada: cleanText(value.prioridade_recomendada) || fallback.prioridade_recomendada,
    recomendacao: cleanText(value.recomendacao) || fallback.recomendacao,
    fontes_utilizadas: Array.isArray(value.fontes_utilizadas)
      ? value.fontes_utilizadas
          .filter((source) => source && typeof source.url === "string")
          .map((source) => ({
            nome: cleanText(source.nome) || "Fonte técnica",
            url: source.url,
            contribuicao: cleanText(source.contribuicao) || "Referência técnica consultada",
          }))
      : fallback.fontes_utilizadas,
    lacunas_de_informacao: Array.isArray(value.lacunas_de_informacao)
      ? value.lacunas_de_informacao.map(cleanText).filter(Boolean)
      : fallback.lacunas_de_informacao,
    nivel_confianca: cleanText(value.nivel_confianca) || fallback.nivel_confianca,
    justificativa_confianca: cleanText(value.justificativa_confianca) || fallback.justificativa_confianca,
  };
}

function deterministicFallback(intelligence: IntelligencePackage): ThreatAnalysis {
  const nvd = intelligence.nvd;
  const cve = intelligence.cveProgram;
  const cisa = intelligence.cisaKev;
  const description = nvd?.description || cve.description || intelligence.seed.description;
  const cwes = nvd?.cwes.join(", ") || "Vulnerabilidade de software";
  const versions = summarizeAffectedVersions(nvd, cve);
  const refs = mergeReferences(nvd?.references ?? [], cve.references ?? []).slice(0, 8);

  return {
    tipo_evento: `${cwes} em ${intelligence.technology}`,
    resumo_executivo: description,
    impacto_tecnico: description,
    produtos_afetados: intelligence.technology,
    versoes_afetadas: versions,
    vetor_ataque: nvd?.cvss.vector || "Não confirmado nas fontes consultadas",
    mecanica_exploracao: description,
    exploracao_ativa: cisa
      ? "Exploração conhecida confirmada por inclusão no catálogo CISA KEV."
      : "Não confirmado nas fontes consultadas.",
    patch_disponivel: refs.some((ref) => ref.tags.some((tag) => /patch|release notes/i.test(tag)))
      ? "Há referência de patch ou nota de versão nas fontes oficiais consultadas."
      : "Não confirmado nas fontes consultadas.",
    mitigacoes_temporarias: intelligence.seed.solution,
    deteccao_soc: "Monitorar logs do produto afetado, eventos de falha, alterações de privilégio e comportamentos anômalos relacionados ao componente vulnerável.",
    indicadores_comprometimento: "Não foram identificados IOCs confirmados nas fontes consultadas.",
    prioridade_recomendada: cisa || (nvd?.cvss.score ?? 0) >= 9 ? "Crítica" : (nvd?.cvss.score ?? 0) >= 7 ? "Alta" : "Média",
    recomendacao: cisa && typeof cisa["requiredAction"] === "string"
      ? String(cisa["requiredAction"])
      : intelligence.seed.solution,
    fontes_utilizadas: refs.map((ref) => ({
      nome: ref.source || new URL(ref.url).hostname,
      url: ref.url,
      contribuicao: ref.tags.join(", ") || "Referência técnica",
    })),
    lacunas_de_informacao: GEMINI_API_KEY
      ? ["A análise automática por IA não pôde ser concluída; foi aplicada contingência baseada nas fontes estruturadas."]
      : ["GEMINI_API_KEY não configurada; o relatório foi produzido sem correlação linguística por IA."],
    nivel_confianca: nvd && cve.available ? "Médio" : "Baixo",
    justificativa_confianca: "A confiança depende da completude das versões, patches e advisories publicados nas fontes estruturadas.",
  };
}

function renderColabStyleReport(
  intelligence: IntelligencePackage,
  analysis: ThreatAnalysis,
): string {
  const cveId = escapeHtml(intelligence.cveId);
  const tech = escapeHtml(intelligence.technology);
  const nvd = intelligence.nvd;
  const score = nvd?.cvss.score ?? parseNumeric(intelligence.seed.cvss);
  const { label, color } = classifySeverity(score, Boolean(intelligence.cisaKev));
  const dateText = new Intl.DateTimeFormat("pt-BR", {
    day: "numeric",
    month: "long",
    year: "numeric",
    timeZone: "America/Recife",
  }).format(new Date());

  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(intelligence.cveId)}`;
  const cveUrl = `https://www.cve.org/CVERecord?id=${encodeURIComponent(intelligence.cveId)}`;
  const cisaUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
  const epssUrl = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(intelligence.cveId)}`;

  let metricBlocks = "";
  if (intelligence.cisaKev) {
    metricBlocks += `
      <div style="margin-top:15px;padding:12px;background-color:#fce4e4;border-left:5px solid #c0392b;border-radius:4px;">
        <strong style="color:#c0392b;font-size:14px;">🚨 EXPLORAÇÃO CONHECIDA (CISA KEV):</strong>
        Esta vulnerabilidade consta no catálogo de vulnerabilidades exploradas conhecidas.
        ${typeof intelligence.cisaKev["requiredAction"] === "string" ? `<br><strong>Ação indicada:</strong> ${escapeHtml(String(intelligence.cisaKev["requiredAction"]))}` : ""}
      </div>`;
  }

  if (intelligence.epss.available && intelligence.epss.probability !== undefined) {
    metricBlocks += `
      <div style="margin-top:10px;padding:12px;background-color:#fff8e1;border-left:5px solid #f39c12;border-radius:4px;">
        <strong style="color:#8a6500;font-size:14px;">📊 PROBABILIDADE EPSS (FIRST):</strong>
        O modelo estima <strong>${(intelligence.epss.probability * 100).toFixed(2)}%</strong> de probabilidade de atividade de exploração nos próximos 30 dias.
        ${intelligence.epss.percentile !== undefined ? `Percentil: <strong>${(intelligence.epss.percentile * 100).toFixed(2)}%</strong>.` : ""}
        Esta métrica não confirma exploração por si só.
      </div>`;
  }

  const vendorReferences = mergeReferences(
    intelligence.nvd?.references ?? [],
    intelligence.cveProgram.references ?? [],
  )
    .slice(0, 10)
    .map((reference) => {
      const name = reference.source || safeHostname(reference.url);
      const tags = reference.tags.length ? ` — ${reference.tags.join(", ")}` : "";
      return `<li><strong>${escapeHtml(name)}:</strong> <a href="${escapeAttribute(reference.url)}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">Abrir referência oficial</a>${escapeHtml(tags)}</li>`;
    })
    .join("");

  const aiSources = analysis.fontes_utilizadas
    .filter((source) => isSafePublicUrl(source.url))
    .map((source) => `<li><strong>${escapeHtml(source.nome)}:</strong> ${escapeHtml(source.contribuicao)} — <a href="${escapeAttribute(source.url)}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">abrir fonte</a></li>`)
    .join("");

  return `
<div style="font-family:Arial,sans-serif;color:#2b2b2b;line-height:1.6;font-size:14px;max-width:800px;margin:20px auto;padding:30px;border:1px solid #dcdcdc;background-color:#ffffff;box-shadow:0 4px 10px rgba(0,0,0,0.06);">
  <p>Prezados,</p>
  <p>Durante as atividades de inteligência técnica, compilamos um boletim referente a uma vulnerabilidade identificada no <strong>${tech}</strong>.</p>

  <h3 style="color:#1a252f;border-bottom:2px solid #1a252f;padding-bottom:5px;margin-top:25px;font-size:16px;">Resumo do Alerta:</h3>
  <ul style="padding-left:20px;margin-top:10px;">
    <li style="margin-bottom:6px;"><strong>Data da compilação:</strong> ${escapeHtml(dateText)}</li>
    <li style="margin-bottom:6px;"><strong>Tipo de evento:</strong> ${escapeHtml(analysis.tipo_evento)}.</li>
    <li style="margin-bottom:6px;"><strong>Resumo executivo:</strong> ${escapeHtml(analysis.resumo_executivo)}</li>
    <li style="margin-bottom:6px;"><strong>Impacto técnico:</strong> ${escapeHtml(analysis.impacto_tecnico)}</li>
    <li style="margin-bottom:6px;"><strong>Prioridade recomendada:</strong> ${escapeHtml(analysis.prioridade_recomendada)}</li>
    <li style="margin-bottom:6px;"><strong>Nível de confiança:</strong> ${escapeHtml(analysis.nivel_confianca)} — ${escapeHtml(analysis.justificativa_confianca)}</li>
  </ul>

  ${metricBlocks}

  <h3 style="color:#1a252f;border-bottom:2px solid #1a252f;padding-bottom:5px;margin-top:25px;font-size:16px;">Detalhes Técnicos da Ameaça (${cveId}):</h3>
  <ul style="padding-left:20px;margin-top:10px;">
    <li style="margin-bottom:6px;"><strong>Classificação Base:</strong> <span style="color:${color};font-weight:bold;">${label}</span>. Índice CVSS de <strong>${score === null ? "N/D" : score}</strong>${nvd?.cvss.vector ? ` — vetor ${escapeHtml(nvd.cvss.vector)}` : ""}.</li>
    <li style="margin-bottom:6px;"><strong>Produtos afetados:</strong> ${escapeHtml(analysis.produtos_afetados)}</li>
    <li style="margin-bottom:6px;"><strong>Versões Afetadas:</strong> ${escapeHtml(analysis.versoes_afetadas)}</li>
    <li style="margin-bottom:6px;"><strong>Vetor de ataque:</strong> ${escapeHtml(analysis.vetor_ataque)}</li>
    <li style="margin-bottom:6px;"><strong>Mecânica da Exploração:</strong> ${escapeHtml(analysis.mecanica_exploracao)}</li>
    <li style="margin-bottom:6px;"><strong>Situação de exploração:</strong> ${escapeHtml(analysis.exploracao_ativa)}</li>
  </ul>

  <h3 style="color:#1a252f;border-bottom:2px solid #1a252f;padding-bottom:5px;margin-top:25px;font-size:16px;">Recomendações e Ações de Mitigação:</h3>
  <p><strong>Patch disponível:</strong> ${escapeHtml(analysis.patch_disponivel)}</p>
  <p><strong>Mitigações temporárias:</strong> ${escapeHtml(analysis.mitigacoes_temporarias)}</p>
  <p><strong>Detecção pelo SOC:</strong> ${escapeHtml(analysis.deteccao_soc)}</p>
  <p><strong>Indicadores de comprometimento:</strong> ${escapeHtml(analysis.indicadores_comprometimento)}</p>
  <p><strong>Ação Técnica:</strong> ${escapeHtml(analysis.recomendacao)}</p>

  <h3 style="color:#1a252f;border-bottom:2px solid #1a252f;padding-bottom:5px;margin-top:25px;font-size:16px;">Fontes de Consulta e Referência Técnica:</h3>
  <ul style="margin:8px 0 0 0;padding-left:20px;line-height:1.8;word-break:break-word;">
    <li><strong>Base Nacional de Vulnerabilidades (NVD/NIST):</strong> <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">Acessar registro no NVD</a></li>
    <li><strong>Programa CVE/MITRE:</strong> <a href="${cveUrl}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">Acessar registro CVE</a></li>
    <li><strong>Catálogo CISA KEV:</strong> <a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">Acessar catálogo</a></li>
    <li><strong>Métrica EPSS/FIRST:</strong> <a href="${epssUrl}" target="_blank" rel="noopener noreferrer" style="color:#0056b3;text-decoration:underline;">Consultar EPSS</a></li>
    ${vendorReferences}
    ${aiSources}
  </ul>
</div>`.trim();
}

function mergeReferences(
  nvdReferences: NvdReference[],
  cveReferences: Array<{ url?: string; name?: string; tags?: string[] }>,
): NvdReference[] {
  const seen = new Set<string>();
  const combined: NvdReference[] = [];

  for (const reference of nvdReferences) {
    if (!reference.url || seen.has(reference.url)) continue;
    seen.add(reference.url);
    combined.push(reference);
  }

  for (const reference of cveReferences) {
    if (!reference.url || seen.has(reference.url)) continue;
    seen.add(reference.url);
    combined.push({
      url: reference.url,
      source: reference.name || "CVE Program",
      tags: reference.tags ?? [],
    });
  }

  return combined.sort((a, b) => referenceScore(b) - referenceScore(a));
}

function referenceScore(reference: NvdReference): number {
  const priority: Record<string, number> = {
    "Vendor Advisory": 100,
    Patch: 95,
    "Release Notes": 90,
    Mitigation: 85,
    "Third Party Advisory": 70,
    "Technical Description": 65,
    Exploit: 50,
  };
  const score = Math.max(0, ...reference.tags.map((tag) => priority[tag] ?? 0));
  return score + (reference.url.includes("nvd.nist.gov") ? 0 : 5);
}

function extractCvss(value: unknown): NvdRecord["cvss"] {
  const metrics = value as Record<string, unknown> | undefined;
  if (!metrics) return emptyCvss();

  const variants: Array<[string, string]> = [
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV2", "2.0"],
  ];

  for (const [key, version] of variants) {
    const entries = metrics[key] as Array<Record<string, unknown>> | undefined;
    if (!entries?.length) continue;
    const entry = entries.find((item) => item["type"] === "Primary") ?? entries[0]!;
    const data = entry["cvssData"] as Record<string, unknown> | undefined;
    return {
      score: numberOrNull(data?.["baseScore"]),
      severity: stringOrNull(data?.["baseSeverity"] ?? entry["baseSeverity"]),
      vector: stringOrNull(data?.["vectorString"]),
      version,
      exploitabilityScore: numberOrNull(entry["exploitabilityScore"]),
      impactScore: numberOrNull(entry["impactScore"]),
    };
  }
  return emptyCvss();
}

function emptyCvss(): NvdRecord["cvss"] {
  return {
    score: null,
    severity: null,
    vector: null,
    version: null,
    exploitabilityScore: null,
    impactScore: null,
  };
}

function extractCwes(value: unknown): string[] {
  const weaknesses = Array.isArray(value) ? value : [];
  const result: string[] = [];
  for (const weakness of weaknesses) {
    const descriptions = (weakness as Record<string, unknown>)["description"];
    if (!Array.isArray(descriptions)) continue;
    for (const item of descriptions) {
      const text = stringOrUndefined((item as Record<string, unknown>)["value"]);
      if (text && !result.includes(text)) result.push(text);
    }
  }
  return result;
}

function extractConfigurations(value: unknown): NvdRecord["affectedConfigurations"] {
  const configurations = Array.isArray(value) ? value : [];
  const result: NvdRecord["affectedConfigurations"] = [];

  function walk(nodeValue: unknown) {
    const node = nodeValue as Record<string, unknown>;
    const matches = Array.isArray(node["cpeMatch"]) ? node["cpeMatch"] : [];
    for (const matchValue of matches) {
      const match = matchValue as Record<string, unknown>;
      result.push({
        criteria: stringOrUndefined(match["criteria"]),
        versionStartIncluding: stringOrUndefined(match["versionStartIncluding"]),
        versionStartExcluding: stringOrUndefined(match["versionStartExcluding"]),
        versionEndIncluding: stringOrUndefined(match["versionEndIncluding"]),
        versionEndExcluding: stringOrUndefined(match["versionEndExcluding"]),
      });
    }
    const children = Array.isArray(node["nodes"]) ? node["nodes"] : [];
    for (const child of children) walk(child);
  }

  for (const configuration of configurations) {
    const nodes = (configuration as Record<string, unknown>)["nodes"];
    if (Array.isArray(nodes)) nodes.forEach(walk);
  }
  return result;
}

function extractNvdReferences(value: unknown): NvdReference[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const reference = item as Record<string, unknown>;
    const url = stringOrUndefined(reference["url"]);
    if (!url) return [];
    return [{
      url,
      source: stringOrUndefined(reference["source"]),
      tags: Array.isArray(reference["tags"])
        ? reference["tags"].filter((tag): tag is string => typeof tag === "string")
        : [],
    }];
  });
}

function chooseDescription(value: unknown): string {
  if (!Array.isArray(value)) return "Sem descrição disponível.";
  const descriptions = value as Array<Record<string, unknown>>;
  for (const lang of ["pt-BR", "pt", "en"]) {
    const item = descriptions.find((entry) => entry["lang"] === lang);
    const text = stringOrUndefined(item?.["value"]);
    if (text) return text;
  }
  return stringOrUndefined(descriptions[0]?.["value"]) ?? "Sem descrição disponível.";
}

function summarizeAffectedVersions(nvd: NvdRecord | null, cve: CveRecord): string {
  if (cve.available && Array.isArray(cve.affected) && cve.affected.length) {
    const text = JSON.stringify(cve.affected).slice(0, 3000);
    return text || "Não confirmado nas fontes consultadas";
  }

  if (nvd?.affectedConfigurations.length) {
    return nvd.affectedConfigurations
      .slice(0, 8)
      .map((item) => {
        const range = [
          item.versionStartIncluding ? `a partir de ${item.versionStartIncluding}` : "",
          item.versionStartExcluding ? `após ${item.versionStartExcluding}` : "",
          item.versionEndIncluding ? `até ${item.versionEndIncluding}` : "",
          item.versionEndExcluding ? `antes de ${item.versionEndExcluding}` : "",
        ].filter(Boolean).join(" ");
        return `${item.criteria ?? "CPE não informado"}${range ? ` (${range})` : ""}`;
      })
      .join("; ");
  }

  return "Não confirmado nas fontes consultadas";
}

function classifySeverity(score: number | null, kev: boolean) {
  if (kev || (score ?? 0) >= 9) return { label: "Crítica", color: "#d32f2f" };
  if ((score ?? 0) >= 7) return { label: "Alta", color: "#f57c00" };
  if ((score ?? 0) >= 4) return { label: "Média", color: "#c69a00" };
  if (score !== null && score > 0) return { label: "Baixa", color: "#3498db" };
  return { label: "Não classificada", color: "#6c757d" };
}

function stripHtml(value: string): string {
  return normalizeWhitespace(
    value
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
      .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'"),
  );
}

function extractHtmlTitle(value: string): string {
  const match = value.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? stripHtml(match[1] ?? "").slice(0, 300) : "";
}

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function stripJsonFence(value: string): string {
  return value.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
}

function cleanText(value: unknown): string {
  return typeof value === "string" ? value.replace(/[*`]/g, "").trim() : "";
}

function isSafePublicUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host.endsWith(".local")) return false;
    if (/^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
    if (host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80")) return false;
    return true;
  } catch {
    return false;
  }
}

function escapeHtml(value: unknown): string {
  return String(value ?? "Não informado")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttribute(value: string): string {
  return escapeHtml(value);
}

function safeHostname(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return "Referência técnica";
  }
}

function parseNumeric(value: string): number | null {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringOrNull(value: unknown): string | null {
  return stringOrUndefined(value) ?? null;
}
