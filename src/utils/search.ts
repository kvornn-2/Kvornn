import type { BulkQueryRow, DatabaseSourceType, IntelRecord, QuerySearchMode, SearchResult } from '../types/intel';
import { decodeSnowflake, isValidSnowflake } from './snowflake.ts';

const PUBLIC_INFO_TEXT_RE =
  /\b(public[_\s-]?info|public|osint|open[_\s-]?source|kamu|acik|açık|profile|profil|bio|whois|rdap|dns|github|gravatar|avatar|directory|social|server[_\s-]?list|bot[_\s-]?list|invite|discord[_\s-]?bio|lookup[_\s-]?public)\b/i;

const LEAK_TEXT_RE =
  /\b(leak|leaked|stealer|infostealer|redline|raccoon|vidar|lumma|combo|combolist|dump|raw[_\s-]?leak|cloud[_\s-]?logs|telegram[_\s-]?logs|logs|citadel|collection)\b/i;

const SIZINTI_TEXT_RE =
  /(sızıntı|sizinti|\bbreach\b|\bihlal\b|\bhacked\b|\bcompromised\b|\bsql\b|\bforum\b|\bdatabase\b|veritaban[ıi]|\bmember[_\s-]?db\b|\bpanel\b|\bmusteri\b|\bmüşteri\b)/i;

const CREDENTIAL_KEY_RE =
  /^(password|pass|pw|pwd|hash|salt|token|auth_token|access_token|cookie|cookies|stealer|stealer_family|malware_path|computer_name|credential|secret)$/i;

export function classifyRecordDatabaseType(rec: IntelRecord): DatabaseSourceType {
  if (rec.dbType === 'leak' || rec.dbType === 'sizinti' || rec.dbType === 'public_info') {
    return rec.dbType;
  }

  const metaText = [rec.source, rec.datasetName, rec.notes]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  const extraEntries = Object.entries(rec.extra || {});
  const extraBlob = extraEntries
    .map(([k, v]) => `${k} ${v}`)
    .join(' ')
    .toLowerCase();
  const combined = `${metaText} ${extraBlob}`;

  const hasCredentialField = extraEntries.some(
    ([k, v]) => CREDENTIAL_KEY_RE.test(k.trim()) && String(v || '').trim() !== '',
  );

  if (LEAK_TEXT_RE.test(metaText) || hasCredentialField || LEAK_TEXT_RE.test(extraBlob)) {
    return 'leak';
  }

  if (PUBLIC_INFO_TEXT_RE.test(metaText) || PUBLIC_INFO_TEXT_RE.test(extraBlob)) {
    return 'public_info';
  }

  if (SIZINTI_TEXT_RE.test(combined)) {
    return 'sizinti';
  }

  const hasPrivatePii =
    Boolean(rec.email?.trim()) ||
    Boolean(rec.ip?.trim()) ||
    Boolean(rec.phone?.trim()) ||
    extraEntries.some(([k, v]) => {
      const val = String(v || '').trim();
      if (!val) return false;
      return /^(tc|tckn|tc_no|kimlik|ssn|passport|iban|hwid|hw_id|device_id|mac|mac_address|address|adres|ev_adresi|ip2|last_ip|reg_ip|login_ip)$/i.test(
        k.trim(),
      );
    });

  return hasPrivatePii ? 'sizinti' : 'public_info';
}

export function detectQueryType(query: string, mode: QuerySearchMode): 'discord_id' | 'email' | 'username' | 'general' {
  if (mode === 'discord_id') return 'discord_id';
  if (mode === 'email') return 'email';
  if (mode === 'username') return 'username';
  if (mode === 'any') return 'general';

  const trimmed = query.trim();
  if (isValidSnowflake(trimmed)) return 'discord_id';
  if (trimmed.includes('@')) return 'email';
  return 'username';
}

const SNOWFLAKE_TOKEN_RE = /(?<!\d)(\d{17,20})(?!\d)/g;
const EMAIL_TOKEN_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const IPV4_TOKEN_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const PHONE_CANDIDATE_RE = /(?:\+?\d[\d\s\-()]{7,19}\d)/g;

const JUNK_USERNAMES = new Set([
  'unknown',
  'null',
  'none',
  'n/a',
  'na',
  'deleted',
  'deleted_user',
  'anonymous',
  'user',
  'admin',
  'test',
  'guest',
  'empty',
  '-',
  '--',
  '—',
]);

const JUNK_IPS = new Set([
  '0.0.0.0',
  '127.0.0.1',
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
  'localhost',
  '::1',
  '::',
]);

const TIMESTAMP_STRING_RE =
  /^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[T\s]+\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?$|^\d{1,2}[-/.]\d{1,2}[-/.]\d{4}(?:[T\s]+\d{1,2}:\d{2}(?::\d{2})?)?$/;

export function isTimestampLikeValue(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  return TIMESTAMP_STRING_RE.test(trimmed);
}

function parseIpv4ToInt(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n < 0 || n > 255) return null;
    out = (out * 256) + n;
  }
  return out >>> 0;
}

const NON_CORRELATABLE_IP_CIDRS: Array<[number, number]> = [
  // RFC1918, Loopback, Link-Local, CGNAT, Unspecified
  [0x00000000, 0xff000000], // 0.0.0.0/8
  [0x0a000000, 0xff000000], // 10.0.0.0/8
  [0x64400000, 0xffc00000], // 100.64.0.0/10
  [0x7f000000, 0xff000000], // 127.0.0.0/8
  [0xa9fe0000, 0xffff0000], // 169.254.0.0/16
  [0xac100000, 0xfff00000], // 172.16.0.0/12
  [0xc0a80000, 0xffff0000], // 192.168.0.0/16
  // Cloudflare edge / proxy IPv4 ranges
  [0x6715f400, 0xfffffc00], // 103.21.244.0/22
  [0x6716c800, 0xfffffc00], // 103.22.200.0/22
  [0x671f0400, 0xfffffc00], // 103.31.4.0/22
  [0x68100000, 0xfff80000], // 104.16.0.0/13
  [0x68180000, 0xfffc0000], // 104.24.0.0/14
  [0x6ca2c000, 0xffffc000], // 108.162.192.0/18
  [0x83004800, 0xfffffc00], // 131.0.72.0/22
  [0x8d654000, 0xffffc000], // 141.101.64.0/18
  [0xa29e0000, 0xfffe0000], // 162.158.0.0/15
  [0xac400000, 0xfff80000], // 172.64.0.0/13
  [0xadf53000, 0xfffff000], // 173.245.48.0/20
  [0xbc726000, 0xfffff000], // 188.114.96.0/20
  [0xbe5df000, 0xfffff000], // 190.93.240.0/20
  [0xc5eaf000, 0xfffffc00], // 197.234.240.0/22
  [0xc6298000, 0xffff8000], // 198.41.128.0/17
];

export function isCorrelatableIp(rawIp: string): boolean {
  const clean = rawIp.trim().toLowerCase();
  if (!clean || JUNK_IPS.has(clean)) return false;
  if (clean.includes(':')) {
    if (
      clean === '::' ||
      clean === '::1' ||
      clean.startsWith('fe80:') ||
      clean.startsWith('fc') ||
      clean.startsWith('fd') ||
      clean.startsWith('2606:4700:') ||
      clean.startsWith('2400:cb00:') ||
      clean.startsWith('2803:f800:') ||
      clean.startsWith('2405:b500:') ||
      clean.startsWith('2405:8100:') ||
      clean.startsWith('2a06:98c0:') ||
      clean.startsWith('2c0f:f248:')
    ) {
      return false;
    }
    return true;
  }
  const ipInt = parseIpv4ToInt(clean);
  if (ipInt === null) return false;
  for (let i = 0; i < NON_CORRELATABLE_IP_CIDRS.length; i++) {
    const [network, mask] = NON_CORRELATABLE_IP_CIDRS[i];
    if ((ipInt & mask) >>> 0 === network >>> 0) {
      return false;
    }
  }
  return true;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function containsExactToken(text: string, token: string): boolean {
  if (!text || !token) return false;
  const trimmed = text.trim();
  if (trimmed.toLowerCase() === token.toLowerCase()) return true;
  if (/^\d{17,20}$/.test(token)) {
    const matches = trimmed.match(SNOWFLAKE_TOKEN_RE);
    return Boolean(matches && matches.includes(token));
  }
  const re = new RegExp(`(^|[\\s,;:|/\\\\"'<>()\\[\\]{}=@!])${escapeRegex(token)}($|[\\s,;:|/\\\\"'<>()\\[\\]{}=])`, 'i');
  return re.test(trimmed);
}

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

export function normalizePhoneKey(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || IPV4_TOKEN_RE.test(trimmed)) return '';
  if (trimmed.includes(':') || isTimestampLikeValue(trimmed)) return '';
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length < 9 || digits.length > 15) return '';
  if (isValidSnowflake(digits)) return '';
  // Reject repeated digits (e.g. 000000000, 111111111) or sequential dummy patterns (123456789)
  if (/^(\d)\1{5,}$/.test(digits)) return '';
  if ('0123456789012345'.includes(digits) || '9876543210987654'.includes(digits)) return '';
  if (/^(123)+1?2?3?$/.test(digits)) return '';
  return digits.length >= 10 ? digits.slice(-10) : digits;
}

const NON_DISCORD_SNOWFLAKE_EXTRA_KEY_RE =
  /^(steam|steam_id|steamid|roblox|roblox_id|tc|tckn|tc_no|kimlik|ssn|passport|iban|phone|tel|gsm|mobile|phone2|tel2|gsm2|secondary_phone|order_id|invoice_id|transaction_id|tx_id|card|hwid|hw_id|device_id|mac|mac_address|serial|uuid|guid|wallet|timestamp|created_at|updated_at|registered_at|last_seen|last_login|port|size|bytes|count|record_count)$/i;

export function extractRecordSnowflakes(rec: IntelRecord): string[] {
  const out = new Set<string>();
  const addFromText = (txt: string) => {
    if (!txt || txt.length < 17) return;
    const matches = txt.match(SNOWFLAKE_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (isValidSnowflake(m)) out.add(m);
    }
  };
  const direct = rec.discordId.trim();
  if (direct) {
    if (isValidSnowflake(direct)) out.add(direct);
    else addFromText(rec.discordId);
  }
  addFromText(rec.username);
  addFromText(rec.source);
  addFromText(rec.notes);
  const extra = rec.extra;
  if (extra) {
    for (const k in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, k)) continue;
      const val = extra[k];
      if (!val || val.length < 17) continue;
      const cleanKey = k.trim().toLowerCase().replace(/[\s-]+/g, '_');
      if (NON_DISCORD_SNOWFLAKE_EXTRA_KEY_RE.test(cleanKey)) continue;
      addFromText(val);
    }
  }
  return Array.from(out);
}

export function extractRecordEmails(rec: IntelRecord): string[] {
  const out = new Set<string>();
  const addFromText = (txt: string) => {
    if (!txt || txt.indexOf('@') === -1) return;
    const matches = txt.match(EMAIL_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      out.add(matches[i].toLowerCase());
    }
  };
  addFromText(rec.email);
  addFromText(rec.username);
  addFromText(rec.source);
  addFromText(rec.notes);
  const extra = rec.extra;
  if (extra) {
    for (const k in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, k)) continue;
      addFromText(extra[k]);
    }
  }
  return Array.from(out);
}

export function extractRecordIps(rec: IntelRecord): string[] {
  const out = new Set<string>();
  const addFromText = (txt: string) => {
    if (!txt || txt.length < 7 || txt.indexOf('.') === -1) return;
    const matches = txt.match(IPV4_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const ip = matches[i];
      if (isCorrelatableIp(ip)) out.add(ip);
    }
  };
  const direct = rec.ip.trim().toLowerCase();
  if (direct && isCorrelatableIp(direct)) {
    if (direct.includes(':') && /^[0-9a-f:]+$/.test(direct)) out.add(direct);
    else addFromText(direct);
  }
  addFromText(rec.notes);
  const extra = rec.extra;
  if (extra) {
    for (const k in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, k)) continue;
      addFromText(extra[k]);
    }
  }
  return Array.from(out);
}

const NON_PHONE_EXTRA_KEY_RE =
  /^(id|uid|user_id|userid|discord_id|ip|ip_address|registration_ip|last_ip|login_ip|ip2|last_login|created_at|updated_at|registered_at|last_seen|timestamp|date|time|tarih|kayit_tarihi|son_giris|expires_at|created|updated|hash|avatar_hash|token|password|pass)$/i;

export function extractRecordPhones(rec: IntelRecord): string[] {
  const out = new Set<string>();
  if (rec.phone) {
    const directKey = normalizePhoneKey(rec.phone);
    if (directKey) out.add(directKey);
  }
  const scanText = (txt: string) => {
    if (!txt || txt.length < 9 || !hasAtLeast9Digits(txt) || isTimestampLikeValue(txt)) return;
    const matches = txt.match(PHONE_CANDIDATE_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const k = normalizePhoneKey(matches[i]);
      if (k) out.add(k);
    }
  };
  scanText(rec.notes);
  const extra = rec.extra;
  if (extra) {
    for (const key in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, key)) continue;
      const val = extra[key];
      if (!val || val.length < 9) continue;
      const cleanKey = key.trim().toLowerCase().replace(/[\s-]+/g, '_');
      if (NON_PHONE_EXTRA_KEY_RE.test(cleanKey)) continue;
      scanText(val);
    }
  }
  return Array.from(out);
}

const EXTRA_USERNAME_KEY_RE =
  /^(username|user|nick|nickname|handle|discord_tag|tag|kullanici|kullanici_adi|display_name|global_name|telegram|tg|instagram|ig|twitter|x_handle)$/i;

const HIGH_SIGNAL_EXTRA_KEY_RE =
  /^(tc|tckn|tc_no|kimlik|ssn|passport|iban|hwid|hw_id|device_id|mac|mac_address|serial|uuid|guid|steam|steam_id|steamid|roblox|roblox_id|telegram|tg|instagram|ig|twitter|x_handle|tiktok|youtube|twitch|kick|github|spotify|wallet|btc|eth|sol|address|adres|ev_adresi|discord_tag|tag|alt_id|backup_id|alt_email|recovery_email|secondary_email|secondary_phone|tel2|gsm2|phone2|full_name|ad_soyad|isim_soyisim)$/i;

const GENERIC_JUNK_VALUES = new Set([
  ...JUNK_USERNAMES,
  ...JUNK_IPS,
  'true',
  'false',
  'yes',
  'no',
  'evet',
  'hayir',
  'hayır',
  '0',
  '1',
  'active',
  'inactive',
  'pending',
  'verified',
  'unverified',
  'default',
  'undefined',
]);

function isValidUsernameToken(raw: string): boolean {
  return (
    raw.length >= 4 &&
    !GENERIC_JUNK_VALUES.has(raw) &&
    !/^\d+$/.test(raw) &&
    !/^[0-9a-f]{4,6}$/.test(raw) &&
    raw.indexOf('@') === -1
  );
}

function canonicalExtraKey(key: string): string {
  return key === 'ad_soyad' || key === 'isim_soyisim' || key === 'full_name'
    ? 'full_name'
    : key === 'adres' || key === 'ev_adresi' || key === 'address'
      ? 'address'
      : key === 'tc' || key === 'tckn' || key === 'tc_no' || key === 'kimlik'
        ? 'national_id'
        : key === 'tg' || key === 'telegram'
          ? 'telegram'
          : key === 'ig' || key === 'instagram'
            ? 'instagram'
            : key === 'hw_id' || key === 'hwid'
              ? 'hwid'
              : key === 'mac_address' || key === 'mac'
                ? 'mac'
                : key === 'steamid' || key === 'steam_id' || key === 'steam'
                  ? 'steam_id'
                  : key === 'roblox_id' || key === 'roblox'
                    ? 'roblox_id'
                    : key;
}

export function extractRecordUsernames(rec: IntelRecord): string[] {
  const out = new Set<string>();
  const addUser = (rawVal: string) => {
    if (!rawVal || rawVal.length < 4) return;
    const raw = rawVal.trim().replace(/^@/, '').toLowerCase();
    if (isValidUsernameToken(raw)) {
      out.add(raw);
    }
  };
  addUser(rec.username);
  const extra = rec.extra;
  if (extra) {
    for (const k in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, k)) continue;
      if (EXTRA_USERNAME_KEY_RE.test(k.trim())) {
        addUser(String(extra[k] || ''));
      }
    }
  }
  return Array.from(out);
}

export function extractRecordExtraIdentifiers(rec: IntelRecord): string[] {
  const out = new Set<string>();
  const extra = rec.extra;
  if (!extra) return [];
  for (const rawKey in extra) {
    if (!Object.prototype.hasOwnProperty.call(extra, rawKey)) continue;
    const key = rawKey.trim().toLowerCase();
    if (!HIGH_SIGNAL_EXTRA_KEY_RE.test(key)) continue;
    const val = String(extra[rawKey] || '').trim().toLowerCase();
    if (val.length < 4 || GENERIC_JUNK_VALUES.has(val)) continue;
    if ((key === 'full_name' || key === 'ad_soyad' || key === 'isim_soyisim') && !/\s+/.test(val) && val.length < 8) {
      continue;
    }
    out.add(`${canonicalExtraKey(key)}:${val}`);
  }
  return Array.from(out);
}

/**
 * Single-pass zero-Set-allocation token extractor for high-throughput disk indexing.
 * Emits exact same typed tokens (`id:`, `em:`, `ip:`, `ph:`, `un:`, `ex:`) as the 6 individual extractors.
 */
export function collectRecordTokens(
  rec: IntelRecord,
  dedupSet: Set<string>,
  emit: (typedKey: string) => void,
): void {
  dedupSet.clear();

  const emitOnce = (typedKey: string) => {
    if (!dedupSet.has(typedKey)) {
      dedupSet.add(typedKey);
      emit(typedKey);
    }
  };

  const scanSnowflakes = (txt: string) => {
    if (!txt || txt.length < 17) return;
    const matches = txt.match(SNOWFLAKE_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (isValidSnowflake(m)) emitOnce(`id:${m}`);
    }
  };

  const scanEmails = (txt: string) => {
    if (!txt || txt.indexOf('@') === -1) return;
    const matches = txt.match(EMAIL_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      emitOnce(`em:${matches[i].toLowerCase()}`);
    }
  };

  const scanIpv4s = (txt: string) => {
    if (!txt || txt.length < 7 || txt.indexOf('.') === -1) return;
    const matches = txt.match(IPV4_TOKEN_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const ip = matches[i];
      if (isCorrelatableIp(ip)) emitOnce(`ip:${ip}`);
    }
  };

  const scanPhones = (txt: string) => {
    if (!txt || txt.length < 9 || !hasAtLeast9Digits(txt) || isTimestampLikeValue(txt)) return;
    const matches = txt.match(PHONE_CANDIDATE_RE);
    if (!matches) return;
    for (let i = 0; i < matches.length; i++) {
      const pk = normalizePhoneKey(matches[i]);
      if (pk) emitOnce(`ph:${pk}`);
    }
  };

  const addUser = (rawVal: string) => {
    if (!rawVal || rawVal.length < 4) return;
    const raw = rawVal.trim().replace(/^@/, '').toLowerCase();
    if (isValidUsernameToken(raw)) {
      emitOnce(`un:${raw}`);
    }
  };

  if (rec.discordId) {
    const directId = rec.discordId.trim();
    if (directId) {
      if (isValidSnowflake(directId)) emitOnce(`id:${directId}`);
      else scanSnowflakes(rec.discordId);
    }
  }

  if (rec.email) scanEmails(rec.email);

  if (rec.ip) {
    const directIp = rec.ip.trim().toLowerCase();
    if (directIp && isCorrelatableIp(directIp)) {
      if (directIp.includes(':') && /^[0-9a-f:]+$/.test(directIp)) {
        emitOnce(`ip:${directIp}`);
      } else {
        scanIpv4s(directIp);
      }
    }
  }

  if (rec.phone) {
    const pk = normalizePhoneKey(rec.phone);
    if (pk) emitOnce(`ph:${pk}`);
  }

  if (rec.username) {
    addUser(rec.username);
    scanSnowflakes(rec.username);
    scanEmails(rec.username);
  }

  if (rec.source) {
    scanSnowflakes(rec.source);
    scanEmails(rec.source);
  }

  if (rec.notes) {
    scanSnowflakes(rec.notes);
    scanEmails(rec.notes);
    scanIpv4s(rec.notes);
    scanPhones(rec.notes);
  }

  const extra = rec.extra;
  if (extra) {
    for (const rawKey in extra) {
      if (!Object.prototype.hasOwnProperty.call(extra, rawKey)) continue;
      const valStr = extra[rawKey];
      if (!valStr) continue;

      const keyTrim = rawKey.trim();
      const keyLower = keyTrim.toLowerCase();
      const cleanKey = keyLower.indexOf(' ') !== -1 || keyLower.indexOf('-') !== -1
        ? keyLower.replace(/[\s-]+/g, '_')
        : keyLower;

      if (valStr.length >= 17 && !NON_DISCORD_SNOWFLAKE_EXTRA_KEY_RE.test(cleanKey)) {
        scanSnowflakes(valStr);
      }
      scanEmails(valStr);
      scanIpv4s(valStr);
      if (valStr.length >= 9 && !NON_PHONE_EXTRA_KEY_RE.test(cleanKey)) {
        scanPhones(valStr);
      }
      if (EXTRA_USERNAME_KEY_RE.test(keyTrim)) {
        addUser(valStr);
      }
      if (HIGH_SIGNAL_EXTRA_KEY_RE.test(keyLower)) {
        const normVal = String(valStr).trim().toLowerCase();
        if (
          normVal.length >= 4 &&
          !GENERIC_JUNK_VALUES.has(normVal) &&
          !((keyLower === 'full_name' || keyLower === 'ad_soyad' || keyLower === 'isim_soyisim') && !/\s+/.test(normVal) && normVal.length < 8)
        ) {
          emitOnce(`ex:${canonicalExtraKey(keyLower)}:${normVal}`);
        }
      }
    }
  }
}

export function hasConflictingDiscordId(
  rec: IntelRecord,
  targetDiscordId: string,
  knownSnowflakes?: string[],
): boolean {
  const cleanTarget = targetDiscordId.trim();
  if (!cleanTarget) return false;
  const direct = rec.discordId.trim();
  if (direct && isValidSnowflake(direct)) {
    return direct !== cleanTarget;
  }
  const sfs = knownSnowflakes || extractRecordSnowflakes(rec);
  if (sfs.length > 0 && !sfs.includes(cleanTarget)) {
    return true;
  }
  return false;
}

export interface IndexedRecordTokens {
  snowflakes: string[];
  emails: string[];
  ips: string[];
  phones: string[];
  usernames: string[];
  extraIds: string[];
}

export interface SearchIndex {
  records: IntelRecord[];
  byId: Map<string, IntelRecord>;
  byDiscordId: Map<string, IntelRecord[]>;
  byEmail: Map<string, IntelRecord[]>;
  byIp: Map<string, IntelRecord[]>;
  byPhone: Map<string, IntelRecord[]>;
  byUsername: Map<string, IntelRecord[]>;
  byExtraIdentifier: Map<string, IntelRecord[]>;
  tokensByRecordId: Map<string, IndexedRecordTokens>;
}

function pushBucket(map: Map<string, IntelRecord[]>, key: string, rec: IntelRecord) {
  const list = map.get(key);
  if (list) list.push(rec);
  else map.set(key, [rec]);
}

export function buildSearchIndex(records: IntelRecord[]): SearchIndex {
  const byId = new Map<string, IntelRecord>();
  const byDiscordId = new Map<string, IntelRecord[]>();
  const byEmail = new Map<string, IntelRecord[]>();
  const byIp = new Map<string, IntelRecord[]>();
  const byPhone = new Map<string, IntelRecord[]>();
  const byUsername = new Map<string, IntelRecord[]>();
  const byExtraIdentifier = new Map<string, IntelRecord[]>();
  const tokensByRecordId = new Map<string, IndexedRecordTokens>();

  for (const rec of records) {
    byId.set(rec.id, rec);
    const snowflakes = extractRecordSnowflakes(rec);
    const emails = extractRecordEmails(rec);
    const ips = extractRecordIps(rec);
    const phones = extractRecordPhones(rec);
    const usernames = extractRecordUsernames(rec);
    const extraIds = extractRecordExtraIdentifiers(rec);

    tokensByRecordId.set(rec.id, { snowflakes, emails, ips, phones, usernames, extraIds });

    for (const id of snowflakes) pushBucket(byDiscordId, id, rec);
    for (const em of emails) pushBucket(byEmail, em, rec);
    for (const ip of ips) pushBucket(byIp, ip, rec);
    for (const ph of phones) pushBucket(byPhone, ph, rec);
    for (const un of usernames) pushBucket(byUsername, un, rec);
    for (const eid of extraIds) pushBucket(byExtraIdentifier, eid, rec);
  }

  return {
    records,
    byId,
    byDiscordId,
    byEmail,
    byIp,
    byPhone,
    byUsername,
    byExtraIdentifier,
    tokensByRecordId,
  };
}

function recordCompletenessScore(rec: IntelRecord): number {
  let score = 0;
  if (rec.discordId) score += 2;
  if (rec.email) score += 2;
  if (rec.username) score += 1;
  if (rec.ip) score += 1;
  if (rec.phone && !isTimestampLikeValue(rec.phone)) score += 1;
  if (rec.source) score += 1;
  if (rec.notes) score += 1;
  score += Math.min(5, Object.keys(rec.extra || {}).length);
  return score;
}

const MAX_WEAK_KEY_BUCKET = 15;
const MAX_STRONG_KEY_BUCKET = 50;

export function searchRecords(
  records: IntelRecord[],
  rawQuery: string,
  mode: QuerySearchMode = 'auto',
  exactMatch: boolean = false,
  correlationPool?: IntelRecord[],
  prebuiltIndex?: SearchIndex,
): SearchResult {
  const started = performance.now();
  const query = rawQuery.trim();
  const detectedType = detectQueryType(query, mode);
  const snowflake = isValidSnowflake(query) ? decodeSnowflake(query) : null;

  if (!query) {
    return {
      query: '',
      detectedType,
      snowflake: null,
      primaryMatches: [],
      relatedMatches: [],
      durationMs: 0,
    };
  }

  const pool = correlationPool || records;
  const useIndexForPrimary = Boolean(prebuiltIndex && prebuiltIndex.records === records);
  const poolIndex =
    prebuiltIndex && prebuiltIndex.records === pool ? prebuiltIndex : buildSearchIndex(pool);

  const qLower = query.toLowerCase();

  const matchesField = (val: string): boolean => {
    if (!val) return false;
    const vLower = val.toLowerCase();
    return exactMatch ? vLower === qLower : vLower.includes(qLower);
  };

  let primaryMatches: IntelRecord[];
  if (exactMatch && detectedType === 'discord_id' && useIndexForPrimary) {
    primaryMatches = [...(prebuiltIndex!.byDiscordId.get(query) || [])];
  } else if (exactMatch && detectedType === 'email' && useIndexForPrimary) {
    primaryMatches = [...(prebuiltIndex!.byEmail.get(qLower) || [])];
  } else if (exactMatch && detectedType === 'username' && mode === 'username' && useIndexForPrimary) {
    primaryMatches = [...(prebuiltIndex!.byUsername.get(qLower.replace(/^@/, '')) || [])];
  } else {
    primaryMatches = records.filter((rec) => {
      if (detectedType === 'discord_id') {
        if (exactMatch) {
          return (
            rec.discordId.trim() === query ||
            containsExactToken(rec.notes, query) ||
            containsExactToken(rec.username, query) ||
            containsExactToken(rec.source, query) ||
            Object.values(rec.extra || {}).some((v) => containsExactToken(v, query))
          );
        }
        return (
          rec.discordId.includes(query) ||
          rec.notes.includes(query) ||
          rec.username.includes(query) ||
          rec.source.includes(query) ||
          Object.values(rec.extra || {}).some((v) => v.includes(query))
        );
      }
      if (detectedType === 'email') {
        if (exactMatch) {
          return (
            rec.email.trim().toLowerCase() === qLower ||
            containsExactToken(rec.notes, query) ||
            containsExactToken(rec.username, query) ||
            containsExactToken(rec.source, query) ||
            Object.values(rec.extra || {}).some((v) => containsExactToken(v, query))
          );
        }
        return (
          matchesField(rec.email) ||
          matchesField(rec.notes) ||
          matchesField(rec.username) ||
          matchesField(rec.source) ||
          Object.values(rec.extra || {}).some((v) => matchesField(v))
        );
      }
      if (detectedType === 'username') {
        if (mode === 'username') {
          return matchesField(rec.username);
        }
        return (
          matchesField(rec.username) ||
          matchesField(rec.discordId) ||
          matchesField(rec.email) ||
          matchesField(rec.notes) ||
          Object.values(rec.extra || {}).some((v) => matchesField(v))
        );
      }
      return (
        matchesField(rec.discordId) ||
        matchesField(rec.email) ||
        matchesField(rec.username) ||
        matchesField(rec.source) ||
        matchesField(rec.ip) ||
        matchesField(rec.phone) ||
        matchesField(rec.notes) ||
        Object.values(rec.extra || {}).some((v) => matchesField(v))
      );
    });
  }

  // Deduplicate primaryMatches and rank richest records first
  const seenPrimary = new Set<string>();
  primaryMatches = primaryMatches
    .filter((r) => {
      if (seenPrimary.has(r.id)) return false;
      seenPrimary.add(r.id);
      return true;
    })
    .sort((a, b) => recordCompletenessScore(b) - recordCompletenessScore(a));

  // Identity-safe transitive cross-file correlation via inverted index
  const relatedIds = new Set<string>();
  const relatedMatches: IntelRecord[] = [];

  const visitedEmails = new Set<string>();
  const visitedDiscordIds = new Set<string>();
  const visitedPhones = new Set<string>();
  const visitedIps = new Set<string>();
  const visitedUsernames = new Set<string>();
  const visitedExtraIds = new Set<string>();

  const pendingEmails = new Set<string>();
  const pendingDiscordIds = new Set<string>();
  const pendingPhones = new Set<string>();
  const pendingIps = new Set<string>();
  const pendingUsernames = new Set<string>();
  const pendingExtraIds = new Set<string>();

  const getTokens = (rec: IntelRecord): IndexedRecordTokens =>
    poolIndex.tokensByRecordId.get(rec.id) || {
      snowflakes: extractRecordSnowflakes(rec),
      emails: extractRecordEmails(rec),
      ips: extractRecordIps(rec),
      phones: extractRecordPhones(rec),
      usernames: extractRecordUsernames(rec),
      extraIds: extractRecordExtraIdentifiers(rec),
    };

  const queueTokens = (rec: IntelRecord, options: { allowIp: boolean; allowUsername: boolean; allowDiscordIds: boolean }) => {
    const tokens = getTokens(rec);
    if (options.allowDiscordIds) {
      for (const id of tokens.snowflakes) {
        if (!visitedDiscordIds.has(id)) pendingDiscordIds.add(id);
      }
    }
    for (const em of tokens.emails) {
      if (!visitedEmails.has(em)) pendingEmails.add(em);
    }
    for (const ph of tokens.phones) {
      if (!visitedPhones.has(ph)) pendingPhones.add(ph);
    }
    if (options.allowIp) {
      for (const ip of tokens.ips) {
        if (isCorrelatableIp(ip) && !visitedIps.has(ip)) pendingIps.add(ip);
      }
    }
    if (options.allowUsername) {
      for (const un of tokens.usernames) {
        if (!visitedUsernames.has(un)) pendingUsernames.add(un);
      }
    }
    for (const eid of tokens.extraIds) {
      if (!visitedExtraIds.has(eid)) pendingExtraIds.add(eid);
    }
  };

  for (const rec of primaryMatches) {
    queueTokens(rec, { allowIp: true, allowUsername: true, allowDiscordIds: true });
  }
  if (detectedType === 'discord_id' && !visitedDiscordIds.has(query)) {
    pendingDiscordIds.add(query);
  } else if (detectedType === 'email' && !visitedEmails.has(qLower)) {
    pendingEmails.add(qLower);
  }

  let hops = 0;
  const MAX_HOPS = 6;
  const MAX_RELATED_CAP = 5000;

  while (
    hops < MAX_HOPS &&
    relatedMatches.length < MAX_RELATED_CAP &&
    (pendingDiscordIds.size > 0 ||
      pendingEmails.size > 0 ||
      pendingPhones.size > 0 ||
      pendingIps.size > 0 ||
      pendingUsernames.size > 0 ||
      pendingExtraIds.size > 0)
  ) {
    hops += 1;
    const waveIds = Array.from(pendingDiscordIds);
    const waveEmails = Array.from(pendingEmails);
    const wavePhones = Array.from(pendingPhones);
    const waveIps = Array.from(pendingIps);
    const waveUsernames = Array.from(pendingUsernames);
    const waveExtraIds = Array.from(pendingExtraIds);

    pendingDiscordIds.clear();
    pendingEmails.clear();
    pendingPhones.clear();
    pendingIps.clear();
    pendingUsernames.clear();
    pendingExtraIds.clear();

    const strongMap = new Map<string, IntelRecord>();
    const weakMap = new Map<string, IntelRecord>();

    const collectBounded = (targetMap: Map<string, IntelRecord>, list: IntelRecord[] | undefined, maxBucketSize: number) => {
      if (!list || list.length === 0) return;
      if (maxBucketSize > 0 && list.length > maxBucketSize) return;
      for (const item of list) {
        targetMap.set(item.id, item);
      }
    };

    for (const id of waveIds) {
      visitedDiscordIds.add(id);
      const isDirectTarget = detectedType !== 'discord_id' || id === query;
      collectBounded(strongMap, poolIndex.byDiscordId.get(id), isDirectTarget ? 0 : MAX_STRONG_KEY_BUCKET);
    }
    for (const em of waveEmails) {
      visitedEmails.add(em);
      collectBounded(strongMap, poolIndex.byEmail.get(em), MAX_STRONG_KEY_BUCKET);
    }
    for (const ph of wavePhones) {
      visitedPhones.add(ph);
      collectBounded(strongMap, poolIndex.byPhone.get(ph), MAX_STRONG_KEY_BUCKET);
    }
    for (const eid of waveExtraIds) {
      visitedExtraIds.add(eid);
      collectBounded(strongMap, poolIndex.byExtraIdentifier.get(eid), MAX_STRONG_KEY_BUCKET);
    }
    // IP & Username are weak contextual join keys: only link if small bucket size
    for (const ip of waveIps) {
      visitedIps.add(ip);
      if (!isCorrelatableIp(ip)) continue;
      collectBounded(weakMap, poolIndex.byIp.get(ip), MAX_WEAK_KEY_BUCKET);
    }
    for (const un of waveUsernames) {
      visitedUsernames.add(un);
      collectBounded(weakMap, poolIndex.byUsername.get(un), MAX_WEAK_KEY_BUCKET);
    }

    for (const rec of strongMap.values()) {
      if (seenPrimary.has(rec.id) || relatedIds.has(rec.id)) continue;
      const tokens = getTokens(rec);
      const hasOtherId = detectedType === 'discord_id' && hasConflictingDiscordId(rec, query, tokens.snowflakes);
      // Do not propagate conflicting account's IPs or foreign Discord IDs outward
      relatedIds.add(rec.id);
      relatedMatches.push(rec);
      queueTokens(rec, {
        allowIp: !hasOtherId,
        allowUsername: true,
        allowDiscordIds: !hasOtherId,
      });
      if (relatedMatches.length >= MAX_RELATED_CAP) break;
    }

    if (relatedMatches.length < MAX_RELATED_CAP) {
      for (const rec of weakMap.values()) {
        if (seenPrimary.has(rec.id) || relatedIds.has(rec.id) || strongMap.has(rec.id)) continue;
        const tokens = getTokens(rec);
        // CRITICAL: Never accept a different Discord ID matched only via IP or Username
        if (detectedType === 'discord_id' && hasConflictingDiscordId(rec, query, tokens.snowflakes)) {
          continue;
        }
        relatedIds.add(rec.id);
        relatedMatches.push(rec);
        // Never chain IP -> another IP or weak-match usernames -> new IPs
        queueTokens(rec, {
          allowIp: false,
          allowUsername: false,
          allowDiscordIds: false,
        });
        if (relatedMatches.length >= MAX_RELATED_CAP) break;
      }
    }
  }

  relatedMatches.sort((a, b) => recordCompletenessScore(b) - recordCompletenessScore(a));

  return {
    query,
    detectedType,
    snowflake,
    primaryMatches,
    relatedMatches,
    durationMs: Math.max(0.1, Number((performance.now() - started).toFixed(2))),
    scanMetrics: {
      scannedRecords: pool.length,
      scannedDatasets: 0,
      scannedBytes: 0,
    },
  };
}

export function formatByteVolume(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(kb >= 100 ? 0 : 1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(mb >= 100 ? 0 : 1)} MB`;
  const gb = mb / 1024;
  if (gb < 1024) return `${gb.toFixed(2)} GB`;
  const tb = gb / 1024;
  return `${tb.toFixed(2)} TB`;
}

export function runBulkLookup(
  records: IntelRecord[],
  rawInput: string,
  prebuiltIndex?: SearchIndex,
): BulkQueryRow[] {
  const tokens = rawInput
    .split(/[\r\n,;\s]+/)
    .map((t) => t.trim())
    .filter(Boolean);

  const uniqueTokens = Array.from(new Set(tokens));
  const index = prebuiltIndex && prebuiltIndex.records === records ? prebuiltIndex : buildSearchIndex(records);

  return uniqueTokens.map((token) => {
    const valid = isValidSnowflake(token);
    if (!valid) {
      return {
        input: token,
        validSnowflake: false,
        snowflake: null,
        matches: [],
      };
    }
    const res = searchRecords(records, token, 'discord_id', true, records, index);
    const dedup = new Map<string, IntelRecord>();
    for (const rec of [...res.primaryMatches, ...res.relatedMatches]) {
      dedup.set(rec.id, rec);
    }
    return {
      input: token,
      validSnowflake: true,
      snowflake: res.snowflake,
      matches: Array.from(dedup.values()),
    };
  });
}

export function filterDatabaseRecords(
  records: IntelRecord[],
  rawSearch: string,
  datasetId?: string,
): IntelRecord[] {
  const filteredByDs = datasetId ? records.filter((r) => r.datasetId === datasetId) : records;
  const q = rawSearch.trim().toLowerCase();
  if (!q) return filteredByDs;

  const qPhone = normalizePhoneKey(q);
  return filteredByDs.filter((r) => {
    if (
      r.discordId.toLowerCase().includes(q) ||
      r.email.toLowerCase().includes(q) ||
      r.username.toLowerCase().includes(q) ||
      r.source.toLowerCase().includes(q) ||
      r.datasetName.toLowerCase().includes(q) ||
      r.ip.toLowerCase().includes(q) ||
      r.phone.toLowerCase().includes(q) ||
      r.notes.toLowerCase().includes(q)
    ) {
      return true;
    }
    if (qPhone && normalizePhoneKey(r.phone) === qPhone) {
      return true;
    }
    return Object.entries(r.extra || {}).some(
      ([k, v]) => k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q),
    );
  });
}

export function maskEmail(email: string): string {
  const trimmed = email.trim();
  const atIdx = trimmed.indexOf('@');
  if (atIdx <= 0) return trimmed;
  const local = trimmed.slice(0, atIdx);
  const domain = trimmed.slice(atIdx + 1);
  const visibleLocal = local.length <= 2 ? local[0] + '*' : local.slice(0, 2) + '*'.repeat(Math.min(5, local.length - 2));
  const dotIdx = domain.lastIndexOf('.');
  if (dotIdx <= 1) {
    return `${visibleLocal}@${domain[0] || '*'}***`;
  }
  const host = domain.slice(0, dotIdx);
  const tld = domain.slice(dotIdx);
  const visibleHost = host.slice(0, 2) + '*'.repeat(Math.min(4, Math.max(1, host.length - 2)));
  return `${visibleLocal}@${visibleHost}${tld}`;
}

export function maskIp(ip: string): string {
  const parts = ip.trim().split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.***.***`;
  }
  if (ip.includes(':')) {
    const segs = ip.split(':');
    return `${segs[0]}:${segs[1] || ''}:***`;
  }
  return ip.slice(0, 3) + '***';
}

export function maskPhone(phone: string): string {
  const clean = phone.trim();
  if (clean.length <= 4) return '****';
  return clean.slice(0, 3) + '*'.repeat(Math.max(2, clean.length - 5)) + clean.slice(-2);
}

const FILENAME_LIKE_SOURCE_RE =
  /^(?:data[-_\s]*(?:part)?[-_\s]*\d+|.*\.(?:csv|txt|json|ndjson|jsonl|sql|log))$/i;

export function sanitizeQuerySource(source: string, datasetName: string): string {
  const s = (source || '').trim();
  if (!s) return '';
  if (datasetName && s.toLowerCase() === datasetName.trim().toLowerCase()) return '';
  if (FILENAME_LIKE_SOURCE_RE.test(s)) return '';
  return s;
}

export function sanitizeRecordsForQueryResponse(records: IntelRecord[]): IntelRecord[] {
  return records.map((r) => {
    const dbType = classifyRecordDatabaseType(r);
    const rawPhone = (r.phone || '').trim();
    const phoneIsTimestamp = isTimestampLikeValue(rawPhone);
    let extra = r.extra || {};
    if (phoneIsTimestamp && !Object.values(extra).some((v) => String(v || '').trim() === rawPhone)) {
      extra = { ...extra, tarih: rawPhone };
    }
    return {
      ...r,
      dbType,
      datasetId: '',
      datasetName: '',
      source: sanitizeQuerySource(r.source, r.datasetName),
      phone: phoneIsTimestamp ? '' : r.phone,
      extra,
    };
  });
}
