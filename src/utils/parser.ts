import type { FieldMapping, IntelRecord } from '../types/intel';
import { isValidSnowflake } from './snowflake.ts';

export interface ParsedTableResult {
  format: 'json' | 'csv' | 'ndjson' | 'text';
  columns: string[];
  rows: Record<string, string>[];
  suggestedMapping: FieldMapping;
  delimiter?: string;
  hasHeader?: boolean;
  isHeterogeneous?: boolean;
}

const DISCORD_ID_KEYS = [
  'discord_id',
  'discordid',
  'discrod_id',
  'dc_id',
  'dc',
  'userid',
  'user_id',
  'uid',
  'id',
  'snowflake',
  'account_id',
  'member_id',
  'author_id',
];
const EMAIL_KEYS = [
  'email',
  'e-mail',
  'eposta',
  'e_posta',
  'eposta_adresi',
  'mail',
  'mail_address',
  'email_address',
  'leaked_email',
  'contact_email',
];
const USERNAME_KEYS = [
  'username',
  'user',
  'name',
  'nick',
  'nickname',
  'handle',
  'tag',
  'discord_tag',
  'global_name',
  'kullanici',
  'kullanici_adi',
  'display_name',
];
const SOURCE_KEYS = ['source', 'breach', 'leak', 'origin', 'kaynak', 'database', 'db', 'platform', 'incident', 'site'];
const IP_KEYS = ['ip', 'ip_address', 'ipaddress', 'ip_adr', 'last_ip', 'ipv4', 'ipv6', 'reg_ip', 'login_ip'];
const PHONE_KEYS = ['phone', 'tel', 'telefon', 'telefon_no', 'phone_number', 'gsm', 'gsm_no', 'mobile', 'phonenumber', 'numara'];
const NOTES_KEYS = ['notes', 'note', 'info', 'details', 'not', 'aciklama', 'metadata', 'extra', 'comment'];

const SNOWFLAKE_INLINE_RE = /(?<!\d)(\d{17,20})(?!\d)/;
const SNOWFLAKE_GLOBAL_RE = /(?<!\d)(\d{17,20})(?!\d)/g;
const EMAIL_INLINE_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const EMAIL_GLOBAL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4_INLINE_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const IPV4_GLOBAL_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const PHONE_CANDIDATE_RE = /(?:\+?\d[\d\s\-()]{7,19}\d)/g;

const INVISIBLE_CHAR_TEST_RE = /[\u200B-\u200D\uFEFF]/;
const INVISIBLE_CHAR_GLOBAL_RE = /[\u200B-\u200D\uFEFF]/g;

function cleanInvisibleChars(str: string): string {
  if (!str) return '';
  if (INVISIBLE_CHAR_TEST_RE.test(str)) {
    return str.replace(INVISIBLE_CHAR_GLOBAL_RE, '').trim();
  }
  return str.trim();
}

function stringifyCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return cleanInvisibleChars(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value).trim();
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function flattenObject(obj: Record<string, unknown>, prefix = ''): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    const value = obj[key];
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const nested = flattenObject(value as Record<string, unknown>, fullKey);
      Object.assign(out, nested);
    } else {
      out[fullKey] = stringifyCell(value);
    }
  }
  return out;
}

function parseCsvLine(line: string, delimiter: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === delimiter && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

function parseCsvLineFast(line: string, delimiter: string): string[] {
  if (line.indexOf('"') === -1) {
    const parts = line.split(delimiter);
    for (let i = 0; i < parts.length; i++) {
      parts[i] = parts[i].trim();
    }
    return parts;
  }
  return parseCsvLine(line, delimiter);
}

function detectDelimiter(lines: string[]): string {
  const candidates = [',', ';', '\t', '|', ':'];
  const sample = lines.slice(0, 15).map((l) => l.replace(/https?:\/\//gi, 'http__//'));
  let bestDelim = ',';
  let bestScore = -1;

  for (const delim of candidates) {
    let minCount = Infinity;
    let maxCount = 0;
    for (let i = 0; i < sample.length; i++) {
      const cnt = parseCsvLine(sample[i], delim).length;
      if (cnt < minCount) minCount = cnt;
      if (cnt > maxCount) maxCount = cnt;
    }
    if (sample.length > 0 && minCount >= 2) {
      const consistency = minCount === maxCount ? 100 : 10;
      const priority = delim === ',' ? 5 : delim === ';' ? 4 : delim === '\t' ? 3 : delim === '|' ? 2 : 1;
      const score = consistency + minCount * 2 + priority;
      if (score > bestScore) {
        bestScore = score;
        bestDelim = delim;
      }
    }
  }

  return bestDelim;
}

function isLikelyHeaderRow(cells: string[]): boolean {
  if (
    cells.some((c) => {
      const t = c.trim();
      if (!t) return false;
      if (t.startsWith('{') || t.startsWith('[')) return true;
      if (/^[a-zA-ZçğıöşüÇĞİÖŞÜ0-9_.-]{2,24}\s*[:=]\s*\S+/.test(t)) return true;
      const sfMatch = t.match(SNOWFLAKE_INLINE_RE);
      if (sfMatch && isValidSnowflake(sfMatch[1])) return true;
      if (EMAIL_INLINE_RE.test(t) || IPV4_INLINE_RE.test(t)) return true;
      const phones = t.match(PHONE_CANDIDATE_RE) || [];
      if (phones.some((p) => isValidPhoneCandidate(p))) return true;
      return false;
    })
  ) {
    return false;
  }

  const knownHeaders = new Set([
    ...DISCORD_ID_KEYS,
    ...EMAIL_KEYS,
    ...USERNAME_KEYS,
    ...SOURCE_KEYS,
    ...IP_KEYS,
    ...PHONE_KEYS,
    ...NOTES_KEYS,
    'password',
    'hash',
    'created_at',
    'date',
  ]);
  const lowered = cells.map((c) => c.toLowerCase().replace(/\s+/g, '_'));
  return lowered.some((c) => knownHeaders.has(c));
}

const DATE_OR_DATETIME_RE =
  /^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[T\s]+\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?$|^\d{1,2}[-/.]\d{1,2}[-/.]\d{4}(?:[T\s]+\d{1,2}:\d{2}(?::\d{2})?)?$/;

const NON_PHONE_COL_RE =
  /^(id|uid|user_id|userid|discord_id|ip|ip_address|registration_ip|last_ip|login_ip|ip2|last_login|created_at|updated_at|registered_at|last_seen|timestamp|date|time|tarih|kayit_tarihi|son_giris|expires_at|created|updated|hash|avatar_hash|token|password|pass)$/i;

function hasAtLeast9Digits(str: string): boolean {
  let digits = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      digits += 1;
      if (digits >= 9) return true;
    }
  }
  return false;
}

export function isValidPhoneCandidate(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed.length < 9 || trimmed.indexOf(':') !== -1 || !hasAtLeast9Digits(trimmed)) return false;
  if (DATE_OR_DATETIME_RE.test(trimmed)) return false;
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length < 9 || digits.length > 15) return false;
  if (IPV4_INLINE_RE.test(trimmed)) return false;
  if (isValidSnowflake(digits)) return false;
  // Reject obvious repeating or sequential dummy digits (e.g. 123456789, 000000000)
  if (/^(\d)\1{6,}$/.test(digits)) return false;
  if ('0123456789012345'.includes(digits) || '9876543210987654'.includes(digits)) return false;
  return true;
}

function splitSqlTuples(valuesClause: string): string[][] {
  const tuples: string[][] = [];
  let i = 0;
  const len = valuesClause.length;

  while (i < len) {
    if (valuesClause[i] !== '(') {
      i++;
      continue;
    }
    i++; // skip '('
    const row: string[] = [];
    let current = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let depth = 0;

    while (i < len) {
      const ch = valuesClause[i];
      if (inSingleQuote) {
        if (ch === '\\' && i + 1 < len) {
          current += valuesClause[i + 1];
          i += 2;
          continue;
        }
        if (ch === "'" && valuesClause[i + 1] === "'") {
          current += "'";
          i += 2;
          continue;
        }
        if (ch === "'") {
          inSingleQuote = false;
        } else {
          current += ch;
        }
        i++;
        continue;
      }
      if (inDoubleQuote) {
        if (ch === '\\' && i + 1 < len) {
          current += valuesClause[i + 1];
          i += 2;
          continue;
        }
        if (ch === '"') {
          inDoubleQuote = false;
        } else {
          current += ch;
        }
        i++;
        continue;
      }

      if (ch === "'") {
        inSingleQuote = true;
      } else if (ch === '"') {
        inDoubleQuote = true;
      } else if (ch === '(') {
        depth++;
        current += ch;
      } else if (ch === ')') {
        if (depth === 0) {
          const val = current.trim();
          row.push(/^null$/i.test(val) ? '' : val);
          i++;
          break;
        }
        depth--;
        current += ch;
      } else if (ch === ',' && depth === 0) {
        const val = current.trim();
        row.push(/^null$/i.test(val) ? '' : val);
        current = '';
      } else {
        current += ch;
      }
      i++;
    }
    if (row.length > 0) {
      tuples.push(row);
    }
  }
  return tuples;
}

function tryParseSqlInserts(text: string): ParsedTableResult | null {
  const headerRe = /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?(?:\s*\(([^)]+)\))?\s+VALUES\s*/gi;
  const rows: Record<string, string>[] = [];
  const colSet = new Set<string>();

  let match: RegExpExecArray | null;
  while ((match = headerRe.exec(text)) !== null) {
    const rawCols = match[1]
      ? match[1]
          .split(',')
          .map((c) => c.replace(/[`"\[\]\s]/g, ''))
          .filter(Boolean)
      : null;

    const valuesStart = match.index + match[0].length;
    const nextInsertIdx = text.slice(valuesStart).search(/;\s*INSERT\s+/i);
    const semiIdx = text.indexOf(';', valuesStart);
    const valuesEnd =
      semiIdx !== -1
        ? semiIdx
        : nextInsertIdx !== -1
          ? valuesStart + nextInsertIdx
          : text.length;

    const valuesSlice = text.slice(valuesStart, valuesEnd);
    const tuples = splitSqlTuples(valuesSlice);
    for (const tuple of tuples) {
      const cols = rawCols && rawCols.length >= tuple.length
        ? rawCols
        : tuple.map((_, idx) => (rawCols && rawCols[idx]) || `sutun_${idx + 1}`);
      const obj: Record<string, string> = {};
      for (let idx = 0; idx < tuple.length; idx++) {
        const colName = cols[idx] || `sutun_${idx + 1}`;
        colSet.add(colName);
        obj[colName] = cleanInvisibleChars(tuple[idx] || '');
      }
      rows.push(obj);
    }
    headerRe.lastIndex = Math.max(headerRe.lastIndex, valuesEnd);
  }

  if (rows.length === 0) return null;
  const columns = Array.from(colSet);
  return {
    format: 'text',
    columns,
    rows,
    suggestedMapping: detectFieldMapping(columns, rows),
  };
}

function isHeterogeneousText(lines: string[], delimiter: string, parsedLines: string[][]): boolean {
  if (lines.length === 0) return false;
  const sample = lines.slice(0, 50);

  // Mixed JSON object lines alongside plain/delimited lines
  const hasJsonLine = sample.some((l) => l.startsWith('{') && l.endsWith('}'));
  if (hasJsonLine) return true;

  const sampleParsed = parsedLines.slice(0, 50);
  const colCounts = sampleParsed.map((c) => c.length);
  let minCols = Infinity;
  let maxCols = 0;
  for (let i = 0; i < colCounts.length; i++) {
    if (colCounts[i] < minCols) minCols = colCounts[i];
    if (colCounts[i] > maxCols) maxCols = colCounts[i];
  }
  if (colCounts.length === 0) minCols = 0;

  // Unstructured or multi-delimiter lines
  if (minCols < 2 && maxCols <= 1) {
    return sample.some(
      (l) =>
        SNOWFLAKE_INLINE_RE.test(l) ||
        EMAIL_INLINE_RE.test(l) ||
        IPV4_INLINE_RE.test(l) ||
        /[;|,\t:]/.test(l),
    );
  }

  // Varying column counts across lines
  const modeCount = [...colCounts]
    .sort((a, b) => colCounts.filter((v) => v === b).length - colCounts.filter((v) => v === a).length)[0];
  const consistentRatio = sampleParsed.filter((c) => c.length === modeCount).length / sampleParsed.length;
  if (consistentRatio < 0.75 || maxCols - minCols > 1) {
    return true;
  }

  // Even when column count matches, if ANY column mixes Snowflakes and Emails across rows, treat as heterogeneous
  for (let colIdx = 0; colIdx < maxCols; colIdx++) {
    let sawSnowflake = false;
    let sawEmail = false;
    for (const cells of sampleParsed) {
      const cell = (cells[colIdx] || '').trim();
      if (!cell) continue;
      if (isValidSnowflake(cell)) sawSnowflake = true;
      if (EMAIL_INLINE_RE.test(cell)) sawEmail = true;
    }
    if (sawSnowflake && sawEmail) {
      return true;
    }
  }

  const otherDelims = [',', ';', '\t', '|', ':'].filter((d) => d !== delimiter);
  for (const cells of sampleParsed) {
    if (cells.length === 1 && otherDelims.some((d) => cells[0].includes(d))) {
      return true;
    }
  }

  return false;
}

function detectBestLineDelimiter(line: string): string | null {
  if (line.indexOf('"') === -1) {
    let tabs = 0;
    let pipes = 0;
    let semis = 0;
    let commas = 0;
    let colons = 0;
    for (let i = 0; i < line.length; i++) {
      const code = line.charCodeAt(i);
      if (code === 9) tabs += 1;
      else if (code === 124) pipes += 1;
      else if (code === 59) semis += 1;
      else if (code === 44) commas += 1;
      else if (code === 58) colons += 1;
    }
    let best: string | null = null;
    let bestHits = 0;
    if (tabs > bestHits) { bestHits = tabs; best = '\t'; }
    if (pipes > bestHits) { bestHits = pipes; best = '|'; }
    if (semis > bestHits) { bestHits = semis; best = ';'; }
    if (commas > bestHits) { bestHits = commas; best = ','; }
    if (colons > bestHits) { bestHits = colons; best = ':'; }
    return best;
  }

  const candidates = ['\t', '|', ';', ',', ':'];
  let best: string | null = null;
  let bestCount = 1;
  for (let c = 0; c < candidates.length; c++) {
    const d = candidates[c];
    const count = parseCsvLine(line, d).length;
    if (count > bestCount) {
      bestCount = count;
      best = d;
    }
  }
  return best;
}

const DISCORD_ID_KEY_SET = new Set(DISCORD_ID_KEYS);
const EMAIL_KEY_SET = new Set(EMAIL_KEYS);
const USERNAME_KEY_SET = new Set(USERNAME_KEYS);
const SOURCE_KEY_SET = new Set(SOURCE_KEYS);
const IP_KEY_SET = new Set(IP_KEYS);
const PHONE_KEY_SET = new Set(PHONE_KEYS);

const MIXED_KV_RE = /^([a-zA-ZçğıöşüÇĞİÖŞÜ0-9_.-]{2,24})\s*[:=]\s*(.+)$/;
const MIXED_SOURCE_HINT_RE = /(leak|breach|dump|forum|db|database|shop|combo|list|logs|20\d{2})/i;
const MIXED_USER_HINT_RE = /^[a-zA-Z0-9_.-]{3,32}(?:#\d{4})?$/;
const MIXED_SKIP_USER_WORD_RE = /^(and|or|with|mail|email|ip|tel|phone|id|user|from|hash|null|none)$/i;

function extractByKeys(
  flat: Record<string, string>,
  keys: string[],
  exclude: Set<string> = new Set(),
): { value: string; matchedKey: string | null } {
  for (const [k, v] of Object.entries(flat)) {
    if (exclude.has(k) || !v.trim()) continue;
    const norm = k.toLowerCase().replace(/[\s.-]+/g, '_');
    const lastSeg = k.split('.').pop()?.toLowerCase().replace(/[\s-]+/g, '_') || norm;
    if (keys.includes(norm) || keys.includes(lastSeg)) {
      return { value: v.trim(), matchedKey: k };
    }
  }
  for (const [k, v] of Object.entries(flat)) {
    if (exclude.has(k) || !v.trim()) continue;
    const lastSeg = (k.split('.').pop() || k).toLowerCase().replace(/[\s-]+/g, '_');
    if (keys.some((cand) => cand.length >= 4 && lastSeg.includes(cand))) {
      return { value: v.trim(), matchedKey: k };
    }
  }
  return { value: '', matchedKey: null };
}

interface ExtractedMixedLine {
  discordId: string;
  email: string;
  username: string;
  source: string;
  ip: string;
  phone: string;
  notes: string;
  extra: Record<string, string>;
}

function extractMixedJsonObjectLine(parsed: Record<string, unknown>): ExtractedMixedLine {
  const flat = flattenObject(parsed);
  const usedKeys = new Set<string>();

  const idPick = extractByKeys(flat, DISCORD_ID_KEYS, usedKeys);
  const idInline = idPick.value.match(SNOWFLAKE_INLINE_RE)?.[1] || '';
  let resolvedId = isValidSnowflake(idInline) ? idInline : '';
  if (resolvedId && idPick.matchedKey) {
    usedKeys.add(idPick.matchedKey);
  } else if (!resolvedId) {
    for (const [fk, fv] of Object.entries(flat)) {
      if (fv.length < 17) continue;
      const m = fv.match(SNOWFLAKE_INLINE_RE);
      if (m && isValidSnowflake(m[1])) {
        resolvedId = m[1];
        if (fv.trim() === m[1]) usedKeys.add(fk);
        break;
      }
    }
  }

  const emailPick = extractByKeys(flat, EMAIL_KEYS, usedKeys);
  let resolvedEmail =
    emailPick.value.indexOf('@') !== -1 && EMAIL_INLINE_RE.test(emailPick.value)
      ? emailPick.value.match(EMAIL_INLINE_RE)?.[0] || ''
      : '';
  if (resolvedEmail && emailPick.matchedKey) {
    usedKeys.add(emailPick.matchedKey);
  } else if (!resolvedEmail) {
    for (const [fk, fv] of Object.entries(flat)) {
      if (usedKeys.has(fk) || fv.indexOf('@') === -1) continue;
      const m = fv.match(EMAIL_INLINE_RE);
      if (m) {
        resolvedEmail = m[0];
        if (fv.trim().toLowerCase() === m[0].toLowerCase()) usedKeys.add(fk);
        break;
      }
    }
  }

  const ipPick = extractByKeys(flat, IP_KEYS, usedKeys);
  let resolvedIp =
    ipPick.value.indexOf('.') !== -1 && IPV4_INLINE_RE.test(ipPick.value)
      ? ipPick.value.match(IPV4_INLINE_RE)?.[0] || ''
      : '';
  if (resolvedIp && ipPick.matchedKey) {
    usedKeys.add(ipPick.matchedKey);
  } else if (!resolvedIp) {
    for (const [fk, fv] of Object.entries(flat)) {
      if (usedKeys.has(fk) || fv.length < 7 || fv.indexOf('.') === -1) continue;
      const m = fv.match(IPV4_INLINE_RE);
      if (m) {
        resolvedIp = m[0];
        if (fv.trim() === m[0]) usedKeys.add(fk);
        break;
      }
    }
  }

  const phonePick = extractByKeys(flat, PHONE_KEYS, usedKeys);
  let resolvedPhone = isValidPhoneCandidate(phonePick.value) ? phonePick.value : '';
  if (resolvedPhone && phonePick.matchedKey) {
    usedKeys.add(phonePick.matchedKey);
  } else if (!resolvedPhone) {
    for (const [fk, fv] of Object.entries(flat)) {
      if (usedKeys.has(fk) || fv.length < 9 || fv.includes(':') || !hasAtLeast9Digits(fv)) continue;
      const leafKey = (fk.split('.').pop() || fk).toLowerCase().replace(/[\s-]+/g, '_');
      if (NON_PHONE_COL_RE.test(leafKey)) continue;
      const matches = fv.match(PHONE_CANDIDATE_RE) || [];
      const hit = matches.find((cand) => isValidPhoneCandidate(cand));
      if (hit) {
        resolvedPhone = hit.trim();
        if (fv.trim() === resolvedPhone) usedKeys.add(fk);
        break;
      }
    }
  }

  const userPick = extractByKeys(flat, USERNAME_KEYS, usedKeys);
  if (userPick.matchedKey) usedKeys.add(userPick.matchedKey);

  const sourcePick = extractByKeys(flat, SOURCE_KEYS, usedKeys);
  if (sourcePick.matchedKey) usedKeys.add(sourcePick.matchedKey);

  const notePick = extractByKeys(flat, NOTES_KEYS, usedKeys);
  if (notePick.matchedKey) usedKeys.add(notePick.matchedKey);

  const extraPairs: string[] = [];
  const extraMap: Record<string, string> = {};
  if (notePick.value) extraPairs.push(notePick.value);
  for (const [k, v] of Object.entries(flat)) {
    if (!usedKeys.has(k) && v.trim()) {
      const cleanedVal = v.trim();
      extraPairs.push(`${k}: ${cleanedVal}`);
      extraMap[k] = cleanedVal;
    }
  }

  return {
    discordId: resolvedId,
    email: resolvedEmail,
    username: userPick.value,
    source: sourcePick.value,
    ip: resolvedIp,
    phone: resolvedPhone,
    notes: extraPairs.join(' | '),
    extra: extraMap,
  };
}

function extractMixedTextLine(line: string, skipInvisibleCheck = false): ExtractedMixedLine {
  const hasProto = line.indexOf('://') !== -1;
  const protectedLine = hasProto ? line.replace(/(https?):\/\//gi, '$1\u0000//') : line;
  const lineDelim = detectBestLineDelimiter(protectedLine);
  const rawTokens = lineDelim ? parseCsvLineFast(protectedLine, lineDelim) : protectedLine.split(/\s+/);
  const tokens: string[] = [];
  for (let i = 0; i < rawTokens.length; i++) {
    let tok = rawTokens[i];
    if (!tok) continue;
    if (hasProto && tok.indexOf('\u0000') !== -1) tok = tok.replace(/\u0000/g, ':');
    tok = skipInvisibleCheck ? tok.trim() : cleanInvisibleChars(tok);
    if (tok) tokens.push(tok);
  }

  const snowflakes = line.length >= 17 ? (line.match(SNOWFLAKE_GLOBAL_RE) || []).filter(isValidSnowflake) : [];
  const emails = line.indexOf('@') !== -1 ? (line.match(EMAIL_GLOBAL_RE) || []) : [];
  const ips = line.length >= 7 && line.indexOf('.') !== -1 ? (line.match(IPV4_GLOBAL_RE) || []) : [];
  let phones: string[] = [];
  if (line.length >= 9 && hasAtLeast9Digits(line)) {
    const rawPhones = line.match(PHONE_CANDIDATE_RE);
    if (rawPhones) {
      phones = rawPhones.map((p) => p.trim()).filter(isValidPhoneCandidate);
    }
  }

  const discordId = snowflakes[0] || '';
  const email = emails[0] || '';
  const emailLower = email.toLowerCase();
  const ip = ips[0] || '';
  const phone = phones[0] || '';

  let username = '';
  let source = '';
  const leftoverNotes: string[] = [];
  const extractedKv: Record<string, string> = {};

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    const hasKvSep = tok.indexOf(':') !== -1 || tok.indexOf('=') !== -1;
    if (hasKvSep) {
      const kvMatch = tok.match(MIXED_KV_RE);
      if (kvMatch) {
        const k = kvMatch[1].toLowerCase();
        const v = kvMatch[2].trim();
        if (DISCORD_ID_KEY_SET.has(k) && isValidSnowflake(v.match(SNOWFLAKE_INLINE_RE)?.[1] || '')) continue;
        if (EMAIL_KEY_SET.has(k) && v.indexOf('@') !== -1 && EMAIL_INLINE_RE.test(v)) continue;
        if (IP_KEY_SET.has(k) && v.indexOf('.') !== -1 && IPV4_INLINE_RE.test(v)) continue;
        if (PHONE_KEY_SET.has(k) && isValidPhoneCandidate(v)) continue;
        if (!username && USERNAME_KEY_SET.has(k)) {
          username = v;
          continue;
        }
        if (!source && SOURCE_KEY_SET.has(k)) {
          source = v;
          continue;
        }
        if (v && !/^https?$/i.test(k)) {
          extractedKv[k] = v;
        }
      }
    }

    if (discordId && (tok === discordId || tok === `<@${discordId}>` || tok === `<@!${discordId}>`)) continue;
    if (email && tok.toLowerCase() === emailLower) continue;
    if (ip && tok === ip) continue;
    if (phone && tok === phone) continue;

    if (
      (tok.length >= 17 && SNOWFLAKE_INLINE_RE.test(tok) && isValidSnowflake(tok.match(SNOWFLAKE_INLINE_RE)?.[1] || '')) ||
      (tok.indexOf('@') !== -1 && EMAIL_INLINE_RE.test(tok)) ||
      (tok.indexOf('.') !== -1 && IPV4_INLINE_RE.test(tok))
    ) {
      leftoverNotes.push(tok);
      continue;
    }

    const firstChar = tok.charCodeAt(0);
    const cleanTok = firstChar === 64 || firstChar === 35 ? tok.slice(1) : tok;
    const isSourceLike =
      tok.length <= 48 &&
      MIXED_SOURCE_HINT_RE.test(tok) &&
      !/\s/.test(tok);

    if (isSourceLike && !source) {
      source = tok;
      continue;
    }

    if (
      lineDelim &&
      !username &&
      cleanTok.length >= 3 &&
      cleanTok.length <= 40 &&
      MIXED_USER_HINT_RE.test(cleanTok) &&
      !/^\d+$/.test(cleanTok) &&
      !MIXED_SKIP_USER_WORD_RE.test(cleanTok)
    ) {
      username = tok;
      continue;
    }

    leftoverNotes.push(tok);
  }

  for (let i = 1; i < snowflakes.length; i++) {
    const extraId = snowflakes[i];
    if (!leftoverNotes.some((n) => n.includes(extraId))) leftoverNotes.push(extraId);
  }
  for (let i = 1; i < emails.length; i++) {
    const extraMail = emails[i];
    const emLow = extraMail.toLowerCase();
    if (!leftoverNotes.some((n) => n.toLowerCase().includes(emLow))) leftoverNotes.push(extraMail);
  }
  for (let i = 1; i < ips.length; i++) {
    const extraIp = ips[i];
    if (!leftoverNotes.some((n) => n.includes(extraIp))) leftoverNotes.push(extraIp);
  }

  return {
    discordId,
    email,
    username,
    source,
    ip,
    phone,
    notes: leftoverNotes.join(' | '),
    extra: extractedKv,
  };
}

function parseMixedSingleLine(line: string): Record<string, string> {
  // Case A: Single JSON object line inside a mixed file
  if (line.charCodeAt(0) === 123 && line.charCodeAt(line.length - 1) === 125) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const res = extractMixedJsonObjectLine(parsed as Record<string, unknown>);
        const outRow: Record<string, string> = {
          discord_id: res.discordId,
          email: res.email,
          username: res.username,
          source: res.source,
          ip: res.ip,
          phone: res.phone,
          notes: res.notes,
        };
        if (Object.keys(res.extra).length > 0) {
          outRow.__extra_json = JSON.stringify(res.extra);
        }
        return outRow;
      }
    } catch {
      // Fall through to general mixed line parsing
    }
  }

  // Case B: Delimited or free-text line
  const res = extractMixedTextLine(line, false);
  const outRow: Record<string, string> = {
    discord_id: res.discordId,
    email: res.email,
    username: res.username,
    source: res.source,
    ip: res.ip,
    phone: res.phone,
    notes: res.notes,
  };
  if (Object.keys(res.extra).length > 0) {
    outRow.__extra_json = JSON.stringify(res.extra);
  }
  return outRow;
}

function isStandardHeteroMapping(mapping: FieldMapping): boolean {
  return (
    (!mapping.discordIdField || mapping.discordIdField === 'discord_id') &&
    (!mapping.emailField || mapping.emailField === 'email') &&
    (!mapping.usernameField || mapping.usernameField === 'username') &&
    (!mapping.sourceField || mapping.sourceField === 'source') &&
    (!mapping.ipField || mapping.ipField === 'ip') &&
    (!mapping.phoneField || mapping.phoneField === 'phone') &&
    (!mapping.notesField || mapping.notesField === 'notes')
  );
}

function parseMixedLineToIntelRecord(
  line: string,
  mapping: FieldMapping,
  datasetId: string,
  datasetName: string,
  idx: number,
  isStandardMapping: boolean,
  mappedFields: Set<string>,
  skipInvisibleCheck = false,
): IntelRecord {
  if (!isStandardMapping) {
    const row = parseMixedSingleLine(line);
    return normalizeSingleRow(row, mapping, datasetId, datasetName, idx, mappedFields, skipInvisibleCheck);
  }

  let extracted: ExtractedMixedLine | null = null;
  if (line.charCodeAt(0) === 123 && line.charCodeAt(line.length - 1) === 125) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        extracted = extractMixedJsonObjectLine(parsed as Record<string, unknown>);
      }
    } catch {
      // Fall through to text parser
    }
  }
  if (!extracted) {
    extracted = extractMixedTextLine(line, skipInvisibleCheck);
  }

  // Match normalizeSingleRow exact semantics cleanly when direct fields are mapped or auto-resolved (null)
  const discordId = !mapping.discordIdField || mapping.discordIdField === 'discord_id' ? extracted.discordId : '';
  const email = !mapping.emailField || mapping.emailField === 'email' ? extracted.email : '';
  const username = mapping.usernameField === 'username' ? extracted.username : '';
  const source = mapping.sourceField === 'source' ? extracted.source : '';
  const ip = !mapping.ipField || mapping.ipField === 'ip' ? extracted.ip : '';
  const phone = !mapping.phoneField || mapping.phoneField === 'phone' ? extracted.phone : '';
  const notes = mapping.notesField === 'notes' ? extracted.notes : '';
  const extra = extracted.extra;
  if (!mapping.discordIdField && extracted.discordId) extra.discord_id = extracted.discordId;
  if (!mapping.emailField && extracted.email) extra.email = extracted.email;
  if (!mapping.usernameField && extracted.username) extra.username = extracted.username;
  if (!mapping.sourceField && extracted.source) extra.source = extracted.source;
  if (!mapping.ipField && extracted.ip) extra.ip = extracted.ip;
  if (!mapping.phoneField && extracted.phone) extra.phone = extracted.phone;
  if (!mapping.notesField && extracted.notes) extra.notes = extracted.notes;

  return {
    id: `${datasetId}_${idx}`,
    datasetId,
    datasetName,
    discordId,
    email,
    username,
    source,
    ip,
    phone,
    notes,
    extra,
  };
}

export function detectFieldMapping(columns: string[], rows: Record<string, string>[]): FieldMapping {
  const findByName = (candidates: string[], exclude: Set<string>): string | null => {
    const normalizedMap = new Map<string, string>();
    const leafMap = new Map<string, string>();
    for (const col of columns) {
      normalizedMap.set(col.toLowerCase().replace(/[\s.-]+/g, '_'), col);
      const leaf = col.split('.').pop()?.toLowerCase().replace(/[\s-]+/g, '_');
      if (leaf && !leafMap.has(leaf)) leafMap.set(leaf, col);
    }
    for (const candidate of candidates) {
      const match = normalizedMap.get(candidate) || leafMap.get(candidate);
      if (match && !exclude.has(match)) return match;
    }
    for (const col of columns) {
      if (exclude.has(col)) continue;
      const leaf = (col.split('.').pop() || col).toLowerCase().replace(/[\s-]+/g, '_');
      if (candidates.some((cand) => cand.length >= 4 && leaf.includes(cand))) {
        return col;
      }
    }
    return null;
  };

  const used = new Set<string>();
  let discordIdField = findByName(DISCORD_ID_KEYS, used);
  if (discordIdField) used.add(discordIdField);

  let emailField = findByName(EMAIL_KEYS, used);
  if (emailField) used.add(emailField);

  let usernameField = findByName(USERNAME_KEYS, used);
  if (usernameField) used.add(usernameField);

  const sourceField = findByName(SOURCE_KEYS, used);
  if (sourceField) used.add(sourceField);

  let ipField = findByName(IP_KEYS, used);
  if (ipField) used.add(ipField);

  let phoneField = findByName(PHONE_KEYS, used);
  if (phoneField) used.add(phoneField);

  const notesField = findByName(NOTES_KEYS, used);
  if (notesField) used.add(notesField);

  const sampleRows = rows.slice(0, 25);
  if (!discordIdField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => isValidSnowflake((r[col] || '').match(SNOWFLAKE_INLINE_RE)?.[1] || '')).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        discordIdField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!emailField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => EMAIL_INLINE_RE.test((r[col] || '').trim())).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        emailField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!ipField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => IPV4_INLINE_RE.test((r[col] || '').trim())).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        ipField = col;
        used.add(col);
        break;
      }
    }
  }

  if (!phoneField && sampleRows.length > 0) {
    for (const col of columns) {
      if (used.has(col)) continue;
      const nonEmpty = sampleRows.filter((r) => r[col]);
      const hits = nonEmpty.filter((r) => isValidPhoneCandidate(r[col] || '')).length;
      if (hits > 0 && hits >= Math.ceil(nonEmpty.length * 0.4)) {
        phoneField = col;
        used.add(col);
        break;
      }
    }
  }

  const NON_USERNAME_FALLBACK_COLS = new Set([
    'password', 'pass', 'pw', 'hash', 'salt', 'token', 'secret', 'key', 'cookie',
    'session', 'address', 'city', 'country', 'created_at', 'updated_at', 'date',
    'timestamp', 'bio', 'auth_token', 'access_token', 'discord_id', 'userid',
    'user_id', 'uid', 'email', 'mail', 'ip', 'ip_address', 'phone', 'tel', 'url', 'avatar',
  ]);
  if (!usernameField && columns.length > 0) {
    for (const col of columns) {
      const normCol = col.toLowerCase().replace(/[\s.-]+/g, '_');
      if (!used.has(col) && !NON_USERNAME_FALLBACK_COLS.has(normCol)) {
        usernameField = col;
        used.add(col);
        break;
      }
    }
  }

  return {
    discordIdField,
    emailField,
    usernameField,
    sourceField,
    ipField,
    phoneField,
    notesField,
  };
}

export function parseDatasetContent(rawText: string, fileName?: string): ParsedTableResult {
  const text = rawText.replace(/^\uFEFF/, '').trim();
  if (!text) {
    throw new Error('İçe aktarılacak veri içeriği boş.');
  }

  // 0. SQL INSERT dumps (.sql or raw INSERT INTO statements)
  if (
    fileName?.toLowerCase().endsWith('.sql') ||
    /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?[\s\S]+VALUES\s*\(/i.test(text.slice(0, 4000))
  ) {
    const sqlResult = tryParseSqlInserts(text);
    if (sqlResult) return sqlResult;
  }

  // 1. Try JSON or pure NDJSON
  if (
    text.startsWith('{') ||
    text.startsWith('[') ||
    fileName?.toLowerCase().endsWith('.json') ||
    fileName?.toLowerCase().endsWith('.jsonl') ||
    fileName?.toLowerCase().endsWith('.ndjson')
  ) {
    try {
      const parsed = JSON.parse(text);
      let arrayData: unknown[] | null = null;
      if (Array.isArray(parsed)) {
        arrayData = parsed;
      } else if (parsed && typeof parsed === 'object') {
        const obj = parsed as Record<string, unknown>;
        for (const key of ['data', 'records', 'users', 'items', 'rows', 'results', 'entries']) {
          if (Array.isArray(obj[key])) {
            arrayData = obj[key] as unknown[];
            break;
          }
        }
        if (!arrayData) {
          arrayData = [obj];
        }
      }

      if (arrayData && arrayData.length > 0) {
        const rows = arrayData
          .filter((item): item is Record<string, unknown> => item !== null && typeof item === 'object' && !Array.isArray(item))
          .map((item) => flattenObject(item));
        if (rows.length > 0) {
          const colSet = new Set<string>();
          for (const r of rows) {
            for (const k of Object.keys(r)) colSet.add(k);
          }
          const columns = Array.from(colSet);
          return {
            format: 'json',
            columns,
            rows,
            suggestedMapping: detectFieldMapping(columns, rows),
          };
        }
      }
    } catch {
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const jsonObjects: Record<string, string>[] = [];
      let allJson = lines.length > 0;
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
            jsonObjects.push(flattenObject(obj as Record<string, unknown>));
          } else {
            allJson = false;
            break;
          }
        } catch {
          allJson = false;
          break;
        }
      }
      if (allJson && jsonObjects.length > 0) {
        const colSet = new Set<string>();
        for (const r of jsonObjects) {
          for (const k of Object.keys(r)) colSet.add(k);
        }
        const columns = Array.from(colSet);
        return {
          format: 'ndjson',
          columns,
          rows: jsonObjects,
          suggestedMapping: detectFieldMapping(columns, jsonObjects),
        };
      }
    }
  }

  // 2. CSV / Delimited / Mixed Text
  const lines = text.split(/\r?\n/).map((l) => cleanInvisibleChars(l)).filter(Boolean);
  if (lines.length === 0) {
    throw new Error('Geçerli bir veri satırı bulunamadı.');
  }

  const delimiter = detectDelimiter(lines);
  const parsedLines = lines.map((line) => parseCsvLine(line, delimiter));

  if (isHeterogeneousText(lines, delimiter, parsedLines)) {
    const hasHeader = parsedLines.length > 1 && isLikelyHeaderRow(parsedLines[0]);
    const startIdx = hasHeader ? 1 : 0;
    const rows = lines.slice(startIdx).map((line) => parseMixedSingleLine(line));
    const columns = ['discord_id', 'email', 'username', 'source', 'ip', 'phone', 'notes'];
    return {
      format: 'text',
      columns,
      rows,
      hasHeader,
      isHeterogeneous: true,
      suggestedMapping: {
        discordIdField: 'discord_id',
        emailField: 'email',
        usernameField: 'username',
        sourceField: 'source',
        ipField: 'ip',
        phoneField: 'phone',
        notesField: 'notes',
      },
    };
  }

  let maxCols = 0;
  for (let i = 0; i < parsedLines.length; i++) {
    if (parsedLines[i].length > maxCols) maxCols = parsedLines[i].length;
  }
  let columns: string[];
  let dataStartIdx = 0;
  const hasHeader = parsedLines.length > 1 && isLikelyHeaderRow(parsedLines[0]);

  if (hasHeader) {
    columns = parsedLines[0].map((col, idx) => col || `sutun_${idx + 1}`);
    dataStartIdx = 1;
  } else {
    columns = Array.from({ length: maxCols }, (_, idx) => `sutun_${idx + 1}`);
    dataStartIdx = 0;
  }

  const seenCols = new Map<string, number>();
  columns = columns.map((col) => {
    const count = seenCols.get(col) || 0;
    seenCols.set(col, count + 1);
    return count === 0 ? col : `${col}_${count + 1}`;
  });

  const rows: Record<string, string>[] = [];
  for (let i = dataStartIdx; i < parsedLines.length; i++) {
    const cells = parsedLines[i];
    if (cells.every((c) => !c)) continue;
    const rowObj: Record<string, string> = {};
    for (let c = 0; c < columns.length; c++) {
      rowObj[columns[c]] = cells[c] ?? '';
    }
    rows.push(rowObj);
  }

  if (rows.length === 0) {
    throw new Error('Veri satırları ayrıştırılamadı.');
  }

  const format = fileName?.toLowerCase().endsWith('.csv') || delimiter === ',' ? 'csv' : 'text';
  return {
    format,
    columns,
    rows,
    delimiter,
    hasHeader,
    isHeterogeneous: false,
    suggestedMapping: detectFieldMapping(columns, rows),
  };
}

export function parseDatasetSample(sampleText: string, fileName?: string, totalFileBytes?: number): ParsedTableResult {
  const cleaned = sampleText.replace(/^\uFEFF/, '');
  const isTruncatedSample = totalFileBytes !== undefined && totalFileBytes > sampleText.length;

  // For truncated text/ndjson/csv/sql slices, drop the potentially cut-off last line
  let sampleToParse = cleaned;
  const trimmedStart = cleaned.trimStart();
  const looksLikeJsonArray = trimmedStart.startsWith('[') || trimmedStart.startsWith('{');

  if (isTruncatedSample && !looksLikeJsonArray) {
    const lastNl = cleaned.lastIndexOf('\n');
    if (lastNl > 0) {
      sampleToParse = cleaned.slice(0, lastNl);
    }
  }

  const extractTruncatedJsonObjects = (): ParsedTableResult | null => {
    const extractedRows: Record<string, string>[] = [];
    const colSet = new Set<string>();
    let depth = 0;
    let inStr = false;
    let escaped = false;
    let objStart = -1;

    for (let i = 0; i < cleaned.length && extractedRows.length < 50; i++) {
      const ch = cleaned[i];
      if (inStr) {
        if (escaped) {
          escaped = false;
        } else if (ch === '\\') {
          escaped = true;
        } else if (ch === '"') {
          inStr = false;
        }
        continue;
      }
      if (ch === '"') {
        inStr = true;
        continue;
      }
      if (ch === '{') {
        if (depth === 0) objStart = i;
        else if (trimmedStart.startsWith('{') && depth === 1 && objStart === -1) objStart = i;
        depth++;
      } else if (ch === '}') {
        depth--;
        if (objStart !== -1 && (depth === 0 || (trimmedStart.startsWith('{') && depth === 1))) {
          const snippet = cleaned.slice(objStart, i + 1);
          try {
            const obj = JSON.parse(snippet) as unknown;
            if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
              const flat = flattenObject(obj as Record<string, unknown>);
              for (const k of Object.keys(flat)) colSet.add(k);
              extractedRows.push(flat);
            }
          } catch {
            // Ignore partial object
          }
          objStart = -1;
        }
      }
    }

    if (extractedRows.length > 0) {
      const columns = Array.from(colSet);
      return {
        format:
          fileName?.toLowerCase().endsWith('.ndjson') || fileName?.toLowerCase().endsWith('.jsonl')
            ? 'ndjson'
            : 'json',
        columns,
        rows: extractedRows,
        suggestedMapping: detectFieldMapping(columns, extractedRows),
      };
    }
    return null;
  };

  if (isTruncatedSample && looksLikeJsonArray) {
    const jsonSample = extractTruncatedJsonObjects();
    if (jsonSample) return jsonSample;
  }

  try {
    return parseDatasetContent(sampleToParse, fileName);
  } catch {
    if (looksLikeJsonArray) {
      const jsonSample = extractTruncatedJsonObjects();
      if (jsonSample) return jsonSample;
    }

    // Fallback to line-based sample parse on truncated multi-line files
    const lastNl = cleaned.lastIndexOf('\n');
    const safeLines = lastNl > 0 ? cleaned.slice(0, lastNl) : cleaned;
    return parseDatasetContent(safeLines, fileName);
  }
}

export function buildMappedFieldSet(mapping: FieldMapping): Set<string> {
  return new Set(
    [
      mapping.discordIdField,
      mapping.emailField,
      mapping.usernameField,
      mapping.sourceField,
      mapping.ipField,
      mapping.phoneField,
      mapping.notesField,
    ].filter((f): f is string => Boolean(f)),
  );
}

export function normalizeSingleRow(
  row: Record<string, string>,
  mapping: FieldMapping,
  datasetId: string,
  datasetName: string,
  idx: number,
  mappedFields: Set<string> = buildMappedFieldSet(mapping),
  skipInvisibleCheck = false,
): IntelRecord {
  const cleanVal = (raw: string): string => {
    if (!raw) return '';
    return skipInvisibleCheck ? raw.trim() : cleanInvisibleChars(raw);
  };

  const extra: Record<string, string> = {};
  if (row.__extra_json) {
    try {
      const parsedExtra = JSON.parse(row.__extra_json) as Record<string, unknown>;
      if (parsedExtra && typeof parsedExtra === 'object' && !Array.isArray(parsedExtra)) {
        for (const ek in parsedExtra) {
          if (!Object.prototype.hasOwnProperty.call(parsedExtra, ek)) continue;
          if (ek === '__proto__' || ek === 'constructor' || ek === 'prototype') continue;
          const cleanEv = cleanVal(String(parsedExtra[ek] ?? ''));
          if (cleanEv) extra[ek] = cleanEv;
        }
      }
    } catch {
      // Ignore malformed internal extra payload
    }
  }

  let discordId = '';
  if (mapping.discordIdField) {
    const rawMapped = cleanVal(row[mapping.discordIdField] || '');
    if (rawMapped) {
      if (isValidSnowflake(rawMapped)) {
        discordId = rawMapped;
      } else if (rawMapped.length >= 17) {
        const inlineMatch = rawMapped.match(SNOWFLAKE_INLINE_RE);
        if (inlineMatch && isValidSnowflake(inlineMatch[1])) {
          discordId = inlineMatch[1];
        } else {
          extra[mapping.discordIdField || 'raw_id'] = rawMapped;
        }
      } else {
        extra[mapping.discordIdField || 'raw_id'] = rawMapped;
      }
    }
  }

  let email = '';
  if (mapping.emailField) {
    const rawMapped = cleanVal(row[mapping.emailField] || '');
    if (rawMapped) {
      const inlineMatch = rawMapped.indexOf('@') !== -1 ? rawMapped.match(EMAIL_INLINE_RE) : null;
      if (inlineMatch) {
        email = inlineMatch[0];
      } else {
        extra[mapping.emailField || 'raw_email'] = rawMapped;
      }
    }
  }

  let ip = '';
  if (mapping.ipField) {
    const rawMapped = cleanVal(row[mapping.ipField] || '');
    if (rawMapped) {
      const ipv4 = rawMapped.indexOf('.') !== -1 ? rawMapped.match(IPV4_INLINE_RE) : null;
      if (ipv4) {
        ip = ipv4[0];
      } else if (rawMapped.includes(':') && /^[0-9a-fA-F:]+$/.test(rawMapped)) {
        ip = rawMapped;
      } else {
        extra[mapping.ipField || 'raw_ip'] = rawMapped;
      }
    }
  }

  let phone = '';
  if (mapping.phoneField) {
    const rawMapped = cleanVal(row[mapping.phoneField] || '');
    if (rawMapped) {
      if (isValidPhoneCandidate(rawMapped)) {
        phone = rawMapped;
      } else if (rawMapped.length >= 9) {
        const candidates = rawMapped.match(PHONE_CANDIDATE_RE) || [];
        const hit = candidates.find((c) => isValidPhoneCandidate(c));
        if (hit) {
          phone = hit.trim();
        } else {
          extra[mapping.phoneField || 'raw_phone'] = rawMapped;
        }
      } else {
        extra[mapping.phoneField || 'raw_phone'] = rawMapped;
      }
    }
  }

  // Single-pass scan for non-mapped extra columns AND fallback resolution of any missing fields
  const needAnyFallback = !discordId || !email || !ip || !phone;
  for (const key in row) {
    if (!Object.prototype.hasOwnProperty.call(row, key) || key === '__extra_json') continue;
    const rawVal = row[key];
    if (!rawVal) continue;
    const cleaned = cleanVal(rawVal);
    if (!cleaned) continue;

    if (!mappedFields.has(key)) {
      extra[key] = cleaned;
    }

    if (!needAnyFallback) continue;

    if (!discordId && cleaned.length >= 17) {
      const match = cleaned.match(SNOWFLAKE_INLINE_RE);
      if (match && isValidSnowflake(match[1])) {
        discordId = match[1];
      }
    }
    if (!email && cleaned.indexOf('@') !== -1) {
      const match = cleaned.match(EMAIL_INLINE_RE);
      if (match) {
        email = match[0];
      }
    }
    if (!ip && cleaned.length >= 7 && cleaned.indexOf('.') !== -1) {
      const match = cleaned.match(IPV4_INLINE_RE);
      if (match) {
        ip = match[0];
      }
    }
    if (
      !phone &&
      cleaned.length >= 9 &&
      key !== mapping.discordIdField &&
      key !== mapping.ipField &&
      key !== mapping.emailField &&
      cleaned.indexOf(':') === -1 &&
      cleaned.indexOf('@') === -1 &&
      hasAtLeast9Digits(cleaned) &&
      !DATE_OR_DATETIME_RE.test(cleaned)
    ) {
      const normCol = (key.split('.').pop() || key).toLowerCase().replace(/[\s-]+/g, '_');
      if (!NON_PHONE_COL_RE.test(normCol)) {
        const candidates = cleaned.match(PHONE_CANDIDATE_RE);
        if (candidates) {
          for (let i = 0; i < candidates.length; i++) {
            if (isValidPhoneCandidate(candidates[i])) {
              phone = candidates[i].trim();
              break;
            }
          }
        }
      }
    }
  }

  return {
    id: `${datasetId}_${idx}`,
    datasetId,
    datasetName,
    discordId,
    email,
    username: mapping.usernameField ? cleanVal(row[mapping.usernameField] || '') : '',
    source: mapping.sourceField ? cleanVal(row[mapping.sourceField] || '') : '',
    ip,
    phone,
    notes: mapping.notesField ? cleanVal(row[mapping.notesField] || '') : '',
    extra,
  };
}

export interface CsvColumnPlan {
  colNames: string[];
  isMapped: boolean[];
  isNonPhoneCol: boolean[];
  discordIdIdx: number;
  emailIdx: number;
  usernameIdx: number;
  sourceIdx: number;
  ipIdx: number;
  phoneIdx: number;
  notesIdx: number;
  discordIdCol: string;
  emailCol: string;
  ipCol: string;
  phoneCol: string;
}

export function createCsvColumnPlan(
  baseColumns: string[],
  mapping: FieldMapping,
  mappedFields: Set<string> = buildMappedFieldSet(mapping),
): CsvColumnPlan {
  const colNames: string[] = new Array(baseColumns.length);
  const isMapped: boolean[] = new Array(baseColumns.length);
  const isNonPhoneCol: boolean[] = new Array(baseColumns.length);
  for (let i = 0; i < baseColumns.length; i++) {
    const colName = baseColumns[i] || `sutun_${i + 1}`;
    colNames[i] = colName;
    isMapped[i] = mappedFields.has(colName);
    const normCol = (colName.split('.').pop() || colName).toLowerCase().replace(/[\s-]+/g, '_');
    isNonPhoneCol[i] = NON_PHONE_COL_RE.test(normCol);
  }
  const idxOf = (field: string | null | undefined): number => (field ? colNames.indexOf(field) : -1);
  return {
    colNames,
    isMapped,
    isNonPhoneCol,
    discordIdIdx: idxOf(mapping.discordIdField),
    emailIdx: idxOf(mapping.emailField),
    usernameIdx: idxOf(mapping.usernameField),
    sourceIdx: idxOf(mapping.sourceField),
    ipIdx: idxOf(mapping.ipField),
    phoneIdx: idxOf(mapping.phoneField),
    notesIdx: idxOf(mapping.notesField),
    discordIdCol: mapping.discordIdField || 'raw_id',
    emailCol: mapping.emailField || 'raw_email',
    ipCol: mapping.ipField || 'raw_ip',
    phoneCol: mapping.phoneField || 'raw_phone',
  };
}

export function normalizeCsvCellsDirect(
  cells: string[],
  plan: CsvColumnPlan,
  mappedFields: Set<string>,
  datasetId: string,
  datasetName: string,
  idx: number,
  skipInvisibleCheck = false,
): IntelRecord {
  const extra: Record<string, string> = {};
  const cleanCell = (c: number): string => {
    if (c < 0 || c >= cells.length) return '';
    const v = cells[c];
    if (!v) return '';
    return skipInvisibleCheck ? v : cleanInvisibleChars(v);
  };

  let discordId = '';
  if (plan.discordIdIdx !== -1) {
    const rawMapped = cleanCell(plan.discordIdIdx);
    if (rawMapped) {
      if (isValidSnowflake(rawMapped)) {
        discordId = rawMapped;
      } else if (rawMapped.length >= 17) {
        const inlineMatch = rawMapped.match(SNOWFLAKE_INLINE_RE);
        if (inlineMatch && isValidSnowflake(inlineMatch[1])) {
          discordId = inlineMatch[1];
        } else {
          extra[plan.discordIdCol] = rawMapped;
        }
      } else {
        extra[plan.discordIdCol] = rawMapped;
      }
    }
  }

  let email = '';
  if (plan.emailIdx !== -1) {
    const rawMapped = cleanCell(plan.emailIdx);
    if (rawMapped) {
      const inlineMatch = rawMapped.indexOf('@') !== -1 ? rawMapped.match(EMAIL_INLINE_RE) : null;
      if (inlineMatch) {
        email = inlineMatch[0];
      } else {
        extra[plan.emailCol] = rawMapped;
      }
    }
  }

  let ip = '';
  if (plan.ipIdx !== -1) {
    const rawMapped = cleanCell(plan.ipIdx);
    if (rawMapped) {
      const ipv4 = rawMapped.indexOf('.') !== -1 ? rawMapped.match(IPV4_INLINE_RE) : null;
      if (ipv4) {
        ip = ipv4[0];
      } else if (rawMapped.indexOf(':') !== -1 && /^[0-9a-fA-F:]+$/.test(rawMapped)) {
        ip = rawMapped;
      } else {
        extra[plan.ipCol] = rawMapped;
      }
    }
  }

  let phone = '';
  if (plan.phoneIdx !== -1) {
    const rawMapped = cleanCell(plan.phoneIdx);
    if (rawMapped) {
      if (isValidPhoneCandidate(rawMapped)) {
        phone = rawMapped;
      } else if (rawMapped.length >= 9 && hasAtLeast9Digits(rawMapped)) {
        const candidates = rawMapped.match(PHONE_CANDIDATE_RE) || [];
        const hit = candidates.find((cand) => isValidPhoneCandidate(cand));
        if (hit) {
          phone = hit.trim();
        } else {
          extra[plan.phoneCol] = rawMapped;
        }
      } else {
        extra[plan.phoneCol] = rawMapped;
      }
    }
  }

  const needAnyFallback = !discordId || !email || !ip || !phone;
  const planLen = plan.colNames.length;
  const cellLen = cells.length;

  for (let c = 0; c < cellLen; c++) {
    const rawVal = cells[c];
    if (!rawVal) continue;
    const cleaned = skipInvisibleCheck ? rawVal : cleanInvisibleChars(rawVal);
    if (!cleaned) continue;

    if (c < planLen) {
      if (!plan.isMapped[c]) {
        extra[plan.colNames[c]] = cleaned;
      }
    } else {
      const ovCol = `sutun_${c + 1}`;
      if (!mappedFields.has(ovCol)) {
        extra[ovCol] = cleaned;
      }
    }

    if (!needAnyFallback) continue;

    if (!discordId && cleaned.length >= 17) {
      const match = cleaned.match(SNOWFLAKE_INLINE_RE);
      if (match && isValidSnowflake(match[1])) {
        discordId = match[1];
      }
    }
    if (!email && cleaned.indexOf('@') !== -1) {
      const match = cleaned.match(EMAIL_INLINE_RE);
      if (match) {
        email = match[0];
      }
    }
    if (!ip && cleaned.length >= 7 && cleaned.indexOf('.') !== -1) {
      const match = cleaned.match(IPV4_INLINE_RE);
      if (match) {
        ip = match[0];
      }
    }
    if (
      !phone &&
      cleaned.length >= 9 &&
      c !== plan.discordIdIdx &&
      c !== plan.ipIdx &&
      c !== plan.emailIdx &&
      cleaned.indexOf(':') === -1 &&
      cleaned.indexOf('@') === -1 &&
      hasAtLeast9Digits(cleaned) &&
      !DATE_OR_DATETIME_RE.test(cleaned)
    ) {
      const nonPhoneCol = c < planLen ? plan.isNonPhoneCol[c] : false;
      if (!nonPhoneCol) {
        const candidates = cleaned.match(PHONE_CANDIDATE_RE);
        if (candidates) {
          for (let i = 0; i < candidates.length; i++) {
            if (isValidPhoneCandidate(candidates[i])) {
              phone = candidates[i].trim();
              break;
            }
          }
        }
      }
    }
  }

  return {
    id: `${datasetId}_${idx}`,
    datasetId,
    datasetName,
    discordId,
    email,
    username: cleanCell(plan.usernameIdx),
    source: cleanCell(plan.sourceIdx),
    ip,
    phone,
    notes: cleanCell(plan.notesIdx),
    extra,
  };
}

export function normalizeRows(
  rows: Record<string, string>[],
  mapping: FieldMapping,
  datasetId: string,
  datasetName: string,
): IntelRecord[] {
  const mappedFields = buildMappedFieldSet(mapping);
  const out: IntelRecord[] = new Array(rows.length);
  for (let i = 0; i < rows.length; i++) {
    out[i] = normalizeSingleRow(rows[i], mapping, datasetId, datasetName, i, mappedFields);
  }
  return out;
}

export {
  cleanInvisibleChars,
  flattenObject,
  isStandardHeteroMapping,
  parseCsvLine,
  parseCsvLineFast,
  parseMixedLineToIntelRecord,
  parseMixedSingleLine,
  splitSqlTuples,
};

export function reNormalizeDatasetRecords(
  records: IntelRecord[],
  oldMapping: FieldMapping | undefined,
  newMapping: FieldMapping,
  datasetId: string,
  datasetName: string,
): { records: IntelRecord[]; columns: string[] } {
  const colSet = new Set<string>();
  const idKey = oldMapping?.discordIdField || 'discordId';
  const emailKey = oldMapping?.emailField || 'email';
  const userKey = oldMapping?.usernameField || 'username';
  const sourceKey = oldMapping?.sourceField || 'source';
  const ipKey = oldMapping?.ipField || 'ip';
  const phoneKey = oldMapping?.phoneField || 'phone';
  const notesKey = oldMapping?.notesField || 'notes';

  const reconstructedRows: Record<string, string>[] = records.map((rec) => {
    const row: Record<string, string> = {};
    for (const [k, v] of Object.entries(rec.extra || {})) {
      if (v) {
        row[k] = v;
        colSet.add(k);
      }
    }
    if (rec.discordId) {
      row[idKey] = rec.discordId;
      colSet.add(idKey);
    }
    if (rec.email) {
      row[emailKey] = rec.email;
      colSet.add(emailKey);
    }
    if (rec.username) {
      row[userKey] = rec.username;
      colSet.add(userKey);
    }
    if (rec.source) {
      row[sourceKey] = rec.source;
      colSet.add(sourceKey);
    }
    if (rec.ip) {
      row[ipKey] = rec.ip;
      colSet.add(ipKey);
    }
    if (rec.phone) {
      row[phoneKey] = rec.phone;
      colSet.add(phoneKey);
    }
    if (rec.notes) {
      row[notesKey] = rec.notes;
      colSet.add(notesKey);
    }
    return row;
  });

  const normalized = normalizeRows(reconstructedRows, newMapping, datasetId, datasetName).map((normRec, idx) => ({
    ...normRec,
    id: records[idx]?.id || normRec.id,
  }));

  return {
    records: normalized,
    columns: Array.from(colSet),
  };
}
