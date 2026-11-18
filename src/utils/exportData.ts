import type { IntelRecord } from '../types/intel';
import { classifyRecordDatabaseType } from './search.ts';

const CORE_CSV_HEADERS = [
  'id',
  'datasetId',
  'datasetName',
  'dbType',
  'discordId',
  'email',
  'username',
  'source',
  'ip',
  'phone',
  'notes',
] as const;

const CORE_HEADER_SET = new Set<string>(CORE_CSV_HEADERS.map((h) => h.toLowerCase()));
const FORMULA_PREFIX_RE = /^[=+\-@\t\r]|^\s+[=+\-@]/;

export function sanitizeCsvCellForExcel(rawValue: unknown): string {
  if (rawValue === null || rawValue === undefined) return '';
  const str = String(rawValue);
  if (!str) return '';

  const neutralized = FORMULA_PREFIX_RE.test(str) ? `'${str}` : str;
  const needsQuotes = /[",\r\n\t]|^'|^\s|\s$/.test(neutralized);
  if (!needsQuotes) return neutralized;
  return `"${neutralized.replace(/"/g, '""')}"`;
}

export function recordsToCsv(records: IntelRecord[]): string {
  const extraKeySet = new Set<string>();
  for (const rec of records) {
    if (!rec.extra || typeof rec.extra !== 'object') continue;
    for (const k of Object.keys(rec.extra)) {
      const clean = k.trim();
      if (clean) extraKeySet.add(clean);
    }
  }

  const extraKeys = Array.from(extraKeySet).sort((a, b) => a.localeCompare(b));
  const extraHeaders = extraKeys.map((k) => (CORE_HEADER_SET.has(k.toLowerCase()) ? `extra_${k}` : k));
  const allHeaders = [...CORE_CSV_HEADERS, ...extraHeaders];

  const lines: string[] = [allHeaders.map((h) => sanitizeCsvCellForExcel(h)).join(',')];

  for (const rec of records) {
    const dbType = classifyRecordDatabaseType(rec);
    const coreValues: string[] = [
      rec.id || '',
      rec.datasetId || '',
      rec.datasetName || '',
      dbType,
      rec.discordId || '',
      rec.email || '',
      rec.username || '',
      rec.source || '',
      rec.ip || '',
      rec.phone || '',
      rec.notes || '',
    ];
    const extraValues = extraKeys.map((k) => {
      const val = rec.extra?.[k];
      return val === undefined || val === null ? '' : String(val);
    });
    const row = [...coreValues, ...extraValues].map((cell) => sanitizeCsvCellForExcel(cell)).join(',');
    lines.push(row);
  }

  return `\uFEFF${lines.join('\r\n')}`;
}

export function recordsToJsonExport(
  records: IntelRecord[],
  meta: { datasetId?: string; datasetName?: string; query?: string } = {},
): string {
  const enriched = records.map((r) => ({
    ...r,
    dbType: classifyRecordDatabaseType(r),
  }));
  const payload = {
    exportedAt: new Date().toISOString(),
    datasetId: meta.datasetId || null,
    datasetName: meta.datasetName || null,
    query: meta.query || null,
    totalRecords: enriched.length,
    records: enriched,
  };
  return enriched.length <= 5000 ? JSON.stringify(payload, null, 2) : JSON.stringify(payload);
}

const TURKISH_CHAR_MAP: Record<string, string> = {
  ç: 'c',
  Ç: 'c',
  ğ: 'g',
  Ğ: 'g',
  ı: 'i',
  İ: 'i',
  ö: 'o',
  Ö: 'o',
  ş: 's',
  Ş: 's',
  ü: 'u',
  Ü: 'u',
};

export function buildSafeExportFilename(
  baseName: string,
  ext: 'csv' | 'json',
  dateIso: string = new Date().toISOString().slice(0, 10),
): string {
  const transliterated = (baseName || '')
    .replace(/[çÇğĞıİöÖşŞüÜ]/g, (ch) => TURKISH_CHAR_MAP[ch] || ch)
    .toLowerCase();
  const slug = transliterated
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  const safeDate = /^\d{4}-\d{2}-\d{2}$/.test(dateIso) ? dateIso : new Date().toISOString().slice(0, 10);
  return `sentarika-${slug || 'veri'}-${safeDate}.${ext}`;
}
