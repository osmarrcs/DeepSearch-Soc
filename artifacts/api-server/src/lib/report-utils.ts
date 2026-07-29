export interface DateRange {
  startDate: string;
  endDate: string;
  start: Date;
  end: Date;
}

export function parseDateRange(startDate: unknown, endDate: unknown, maxDays = 370): DateRange {
  const startText = typeof startDate === "string" ? startDate.trim() : "";
  const endText = typeof endDate === "string" ? endDate.trim() : "";
  const pattern = /^\d{4}-\d{2}-\d{2}$/;
  if (!pattern.test(startText) || !pattern.test(endText)) {
    throw new Error("Informe as datas no formato YYYY-MM-DD.");
  }

  const start = new Date(`${startText}T00:00:00.000Z`);
  const end = new Date(`${endText}T23:59:59.999Z`);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    throw new Error("Período inválido.");
  }
  if (start > end) throw new Error("A data inicial não pode ser posterior à data final.");

  const days = Math.ceil((end.getTime() - start.getTime()) / 86_400_000) + 1;
  if (days > maxDays) throw new Error(`O período máximo permitido é de ${maxDays} dias.`);

  return { startDate: startText, endDate: endText, start, end };
}

export function addUtcDays(dateText: string, days: number): string {
  const date = new Date(`${dateText}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function safeText(value: unknown, fallback = "Não informado"): string {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return fallback;
}

export function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

export function arrayValue<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function formatDatePt(dateText: string): string {
  const date = new Date(`${dateText}T12:00:00.000Z`);
  return new Intl.DateTimeFormat("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
}

export function truncate(value: string, max = 120): string {
  return value.length <= max ? value : `${value.slice(0, Math.max(0, max - 1))}…`;
}

export function severityColor(label: string): string {
  const normalized = label.toLowerCase();
  if (normalized.includes("crít") || normalized.includes("critical")) return "#d32f2f";
  if (normalized.includes("important") || normalized.includes("alta") || normalized.includes("high")) return "#f57c00";
  if (normalized.includes("moder") || normalized.includes("média") || normalized.includes("medium")) return "#c69a00";
  if (normalized.includes("low") || normalized.includes("baixa")) return "#3498db";
  return "#6c757d";
}

export function uniqueStrings(values: Array<string | undefined | null>): string[] {
  return Array.from(new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value))));
}
