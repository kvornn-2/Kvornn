import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import type {
  EmailOsintIdentitySummary,
  EmailOsintReport,
  EmailOsintSourceResult,
  IntelRecord,
} from '../src/types/intel.ts';
import {
  extractRecordExtraIdentifiers,
  extractRecordIps,
  extractRecordPhones,
  extractRecordSnowflakes,
  isTimestampLikeValue,
  searchRecords,
  type SearchIndex,
} from '../src/utils/search.ts';
import { checkDisposableEmail } from './disposable.ts';

type Lang = 'tr' | 'en';

const ROLE_PREFIX_RE =
  /^(admin|administrator|postmaster|hostmaster|webmaster|abuse|security|noc|support|help|info|contact|sales|billing|noreply|no-reply|hello|team|hr)$/i;

function computeCanonicalEmail(email: string): { canonical: string; isRoleAddress: boolean } {
  const [localRaw = '', domain = ''] = email.trim().toLowerCase().split('@');
  const plusIdx = localRaw.indexOf('+');
  const baseLocal = plusIdx >= 0 ? localRaw.slice(0, plusIdx) : localRaw;
  const isRoleAddress = ROLE_PREFIX_RE.test(baseLocal);
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    const dotless = baseLocal.replace(/\./g, '');
    return { canonical: `${dotless}@gmail.com`, isRoleAddress };
  }
  return { canonical: `${baseLocal}@${domain}`, isRoleAddress };
}

function evaluateSpoofingRisk(spfRecord: string | null, dmarcRecord: string | null): 'low' | 'medium' | 'high' {
  const spfLower = (spfRecord || '').toLowerCase();
  const dmarcLower = (dmarcRecord || '').toLowerCase();
  const hasStrictSpf = spfLower.includes('-all');
  const hasSoftSpf = Boolean(spfRecord) && (spfLower.includes('~all') || spfLower.includes('?all'));
  const hasRejectDmarc = /p=(reject|quarantine)/i.test(dmarcLower);

  if (hasStrictSpf && hasRejectDmarc) return 'low';
  if (spfRecord || dmarcRecord || hasSoftSpf) return 'medium';
  return 'high';
}

function detectMailProvider(mxHosts: string[], domain: string, lang: Lang): string {
  const joined = mxHosts.join(' ').toLowerCase();
  if (joined.includes('google') || joined.includes('gmail-smtp-in')) return 'Google / Gmail';
  if (joined.includes('outlook') || joined.includes('protection.outlook.com')) return 'Microsoft 365 / Outlook';
  if (joined.includes('protonmail') || joined.includes('proton.ch')) return 'Proton Mail';
  if (joined.includes('yandex')) return 'Yandex Mail';
  if (joined.includes('icloud') || joined.includes('me.com')) return 'Apple iCloud Mail';
  if (joined.includes('yahoodns')) return 'Yahoo Mail';
  if (joined.includes('zoho')) return 'Zoho Mail';
  if (joined.includes('fastmail')) return 'Fastmail';
  if (mxHosts.length > 0) return lang === 'tr' ? `Özel / Diğer (${mxHosts[0]})` : `Custom / Other (${mxHosts[0]})`;
  if (domain === 'example.test' || domain === 'demo.invalid') {
    return lang === 'tr' ? 'RFC-2606 Test Alan Adı' : 'RFC-2606 Test Domain';
  }
  return lang === 'tr' ? 'MX Kaydı Bulunamadı' : 'No MX Record Found';
}

async function fetchWithTimeout(
  url: string,
  headers: Record<string, string> = {},
  timeoutMs = 5000,
): Promise<Response> {
  return fetch(url, {
    headers: {
      'User-Agent': 'Sentarika-Archive-OSINT/1.0',
      Accept: 'application/json, text/plain;q=0.9',
      ...headers,
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
}

async function checkXposedOrNot(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'XposedOrNot Sızıntı İndeksi' : 'XposedOrNot Breach Index';
  try {
    const url = `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`;
    const res = await fetchWithTimeout(url, {}, 5200);
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'XposedOrNot genel indeksinde kayıtlı sızıntı bulunamadı.'
            : 'No breaches found in XposedOrNot public index.',
        details: {},
      };
    }
    if (!res.ok) {
      return {
        source: srcName,
        status: 'error',
        summary: `HTTP ${res.status}`,
        details: {},
      };
    }

    const data = (await res.json()) as {
      BreachesSummary?: { site?: string };
      BreachMetrics?: { risk?: Array<{ risk_label?: string; risk_score?: number }> } | null;
      ExposedBreaches?: {
        breaches_details?: Array<{
          breach?: string;
          domain?: string;
          xposed_date?: string;
          xposed_data?: string;
          xposed_records?: number;
          password_risk?: string;
        }>;
      } | null;
      ExposedPastes?: unknown;
    };

    const detailsList = data.ExposedBreaches?.breaches_details || [];
    const summarySites = (data.BreachesSummary?.site || '')
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);

    if (detailsList.length === 0 && summarySites.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'XposedOrNot genel indeksinde kayıtlı sızıntı bulunamadı.'
            : 'No breaches found in XposedOrNot public index.',
        details: {},
      };
    }

    const totalCount = Math.max(detailsList.length, summarySites.length);
    const exposedTypes = new Set<string>();
    const formattedBreaches = detailsList.slice(0, 15).map((b) => {
      if (b.xposed_data) {
        b.xposed_data
          .split(';')
          .map((x) => x.trim())
          .filter(Boolean)
          .forEach((x) => exposedTypes.add(x));
      }
      const parts = [b.breach || b.domain || ''];
      if (b.xposed_date) parts.push(`(${b.xposed_date})`);
      if (b.xposed_data) parts.push(`[${b.xposed_data}]`);
      return parts.filter(Boolean).join(' ');
    });

    const risk = data.BreachMetrics?.risk?.[0];
    const details: Record<string, string | string[]> = {};
    if (risk?.risk_label) {
      details[lang === 'tr' ? 'riskSkoru' : 'riskScore'] = `${risk.risk_label} (${risk.risk_score ?? 0}/100)`;
    }
    if (exposedTypes.size > 0) {
      details[lang === 'tr' ? 'sizdirilanVeriTurleri' : 'exposedDataTypes'] = Array.from(exposedTypes);
    }
    if (formattedBreaches.length > 0) {
      details[lang === 'tr' ? 'ihlalDetaylari' : 'breachDetails'] = formattedBreaches;
    } else if (summarySites.length > 0) {
      details[lang === 'tr' ? 'ihlalKaynaklari' : 'breaches'] = summarySites.slice(0, 20);
    }

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${totalCount} adet doğrulanmış veri ihlalinde tespit edildi.`
          : `Detected in ${totalCount} public data breaches.`,
      details,
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Servise zaman aşımı nedeniyle ulaşılamadı.' : 'Service timed out.',
      details: {},
    };
  }
}

async function checkLeakCheckPublic(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'LeakCheck Genel Sızıntı DB' : 'LeakCheck Public Breach DB';
  try {
    const res = await fetchWithTimeout(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as {
      success?: boolean;
      found?: number;
      fields?: string[];
      sources?: Array<{ name?: string; date?: string }>;
      error?: string;
    };
    const found = Number(data.found || 0);
    if (!data.success || found === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'LeakCheck genel veri tabanında eşleşme bulunamadı.'
            : 'No matches found in LeakCheck public database.',
        details: {},
      };
    }
    const sourceList = (data.sources || [])
      .slice(0, 20)
      .map((s) => (s.date ? `${s.name || 'Kaynak'} (${s.date})` : String(s.name || 'Kaynak')));
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${found.toLocaleString('tr-TR')} sızıntı kaydı tespit edildi.`
          : `Found in ${found.toLocaleString('en-US')} leaked records.`,
      details: {
        ...(sourceList.length > 0 ? { [lang === 'tr' ? 'kaynaklar' : 'sources']: sourceList } : {}),
        ...(data.fields?.length ? { [lang === 'tr' ? 'sizdirilanAlanlar' : 'exposedFields']: data.fields } : {}),
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'LeakCheck servisine ulaşılamadı.' : 'Could not reach LeakCheck.',
      details: {},
    };
  }
}

async function checkHudsonRock(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = 'Hudson Rock Infostealer DB';
  try {
    const res = await fetchWithTimeout(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as {
      message?: string;
      stealers?: Array<{
        date_compromised?: string;
        stealer_family?: string;
        computer_name?: string;
        operating_system?: string;
        malware_path?: string;
        antiviruses?: string[];
        ip?: string;
        top_logins?: string[];
        top_passwords?: string[];
        total_user_services?: number;
        total_corporate_services?: number;
      }>;
    };
    const stealers = Array.isArray(data.stealers) ? data.stealers : [];
    if (stealers.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Infostealer zararlı yazılım kayıtlarında bu e-posta görülmedi.'
            : 'No infostealer compromises associated with this email.',
        details: {},
      };
    }

    const isPresent = (val?: string) => Boolean(val && val !== 'Not Found');
    const logs = stealers.slice(0, 5).map((s, idx) => {
      const parts: string[] = [`#${idx + 1}`];
      if (s.date_compromised) parts.push(s.date_compromised.slice(0, 10));
      if (isPresent(s.stealer_family)) parts.push(`Stealer: ${s.stealer_family}`);
      if (isPresent(s.computer_name)) parts.push(`PC: ${s.computer_name}`);
      if (isPresent(s.operating_system)) parts.push(`OS: ${s.operating_system}`);
      if (isPresent(s.ip)) parts.push(`IP: ${s.ip}`);
      if (isPresent(s.malware_path)) parts.push(`Path: ${s.malware_path}`);
      if (Array.isArray(s.antiviruses) && s.antiviruses.length > 0) {
        parts.push(`AV: ${s.antiviruses.join(', ')}`);
      }
      if (typeof s.total_user_services === 'number') {
        parts.push(`UserSvc: ${s.total_user_services}`);
      }
      if (typeof s.total_corporate_services === 'number' && s.total_corporate_services > 0) {
        parts.push(`CorpSvc: ${s.total_corporate_services}`);
      }
      return parts.join(' | ');
    });

    const topLogins = Array.from(new Set(stealers.flatMap((s) => s.top_logins || []).filter(Boolean))).slice(0, 10);
    const topPasswords = Array.from(new Set(stealers.flatMap((s) => s.top_passwords || []).filter(Boolean))).slice(0, 10);

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${stealers.length} infostealer cihaz kaydında bu e-posta tespit edildi.`
          : `Detected in ${stealers.length} infostealer compromise logs.`,
      details: {
        [lang === 'tr' ? 'cihazKayitlari' : 'compromiseLogs']: logs,
        ...(topLogins.length > 0 ? { [lang === 'tr' ? 'iliskiliHesaplar' : 'topLogins']: topLogins } : {}),
        ...(topPasswords.length > 0 ? { [lang === 'tr' ? 'sifreOrnekleri' : 'topPasswords']: topPasswords } : {}),
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Hudson Rock API zaman aşımı.' : 'Hudson Rock API timed out.',
      details: {},
    };
  }
}

async function checkProxyNovaComb(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'ProxyNova COMB Sızıntı İndeksi' : 'ProxyNova COMB Breach Index';
  try {
    const res = await fetchWithTimeout(
      `https://api.proxynova.com/comb?query=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as { count?: number; lines?: string[] };
    const normalizedEmail = email.trim().toLowerCase();
    const rawLines = Array.isArray(data.lines) ? data.lines.map((l) => String(l).trim()).filter(Boolean) : [];
    const exactLines = rawLines.filter((line) => {
      const lower = line.toLowerCase();
      return lower === normalizedEmail || lower.startsWith(`${normalizedEmail}:`) || lower.startsWith(`${normalizedEmail};`);
    });

    if (exactLines.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Bu e-posta adresi için COMB arşivinde birebir eşleşen kayıt bulunamadı.'
            : 'No exact matching records found for this email in COMB archive.',
        details: {},
      };
    }

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `COMB sızıntı arşivinde birebir eşleşen ${exactLines.length} kayıt bulundu.`
          : `Found ${exactLines.length} exact matching record(s) in COMB breach archive.`,
      details: {
        [lang === 'tr' ? 'birebirEslesenSayisi' : 'exactMatchCount']: String(exactLines.length),
        [lang === 'tr' ? 'kayitlar' : 'records']: exactLines,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'ProxyNova COMB indeksine ulaşılamadı.' : 'Could not reach ProxyNova COMB index.',
      details: {},
    };
  }
}

async function checkProtonPgp(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'Proton / PGP Anahtar Dizini' : 'Proton / PGP Key Directory';
  try {
    const res = await fetchWithTimeout(
      `https://api.protonmail.ch/pks/lookup?op=index&search=${encodeURIComponent(email)}`,
      {},
      4200,
    );
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Proton PGP anahtar sunucusunda kayıt bulunamadı.'
            : 'No key registered in Proton PGP directory.',
        details: {},
      };
    }
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const text = await res.text();
    const pubLine = text.split('\n').find((l) => l.startsWith('pub:'));
    if (!pubLine) {
      return {
        source: srcName,
        status: 'not_found',
        summary: lang === 'tr' ? 'PGP anahtarı bulunamadı.' : 'No PGP key found.',
        details: {},
      };
    }
    const parts = pubLine.split(':');
    const createdTs = Number(parts[4] || 0);
    const createdIso = createdTs > 0 ? new Date(createdTs * 1000).toISOString().slice(0, 10) : '—';
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `Doğrulanmış Proton / PGP açık anahtarı bulundu (Oluşturulma: ${createdIso}).`
          : `Verified Proton / PGP public key found (Created: ${createdIso}).`,
      details: {
        fingerprint: parts[1] || '',
        [lang === 'tr' ? 'olusturulma' : 'created']: createdIso,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Proton anahtar dizinine ulaşılamadı.' : 'Could not reach Proton keyserver.',
      details: {},
    };
  }
}

async function checkOpenPgp(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = 'OpenPGP Keyserver';
  try {
    const res = await fetchWithTimeout(
      `https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`,
      {},
      4000,
    );
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'OpenPGP genel anahtar sunucusunda kayıtlı anahtar yok.'
            : 'No public key found on keys.openpgp.org.',
        details: {},
      };
    }
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? 'OpenPGP üzerinde bu e-postaya bağlı herkese açık PGP anahtarı mevcut.'
          : 'Public PGP key is registered on OpenPGP for this email.',
      details: {
        url: `https://keys.openpgp.org/search?q=${encodeURIComponent(email)}`,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'OpenPGP sunucusu yanıt vermedi.' : 'OpenPGP server did not respond.',
      details: {},
    };
  }
}

interface UbuntuPgpResult {
  check: EmailOsintSourceResult;
  uids: string[];
  altEmails: string[];
}

async function checkUbuntuKeyserver(email: string, lang: Lang): Promise<UbuntuPgpResult> {
  const srcName = 'Ubuntu / SKS PGP Keyserver';
  try {
    const res = await fetchWithTimeout(
      `https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search=${encodeURIComponent(email)}`,
      {},
      4200,
    );
    if (res.status === 404) {
      return {
        check: {
          source: srcName,
          status: 'not_found',
          summary: lang === 'tr' ? 'Ubuntu PGP anahtar arşivinde kayıt yok.' : 'No public PGP key on keyserver.ubuntu.com.',
          details: {},
        },
        uids: [],
        altEmails: [],
      };
    }
    if (!res.ok) {
      return {
        check: { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} },
        uids: [],
        altEmails: [],
      };
    }
    const text = await res.text();
    const lines = text.split('\n');
    const pubKeys = lines.filter((l) => l.startsWith('pub:'));
    const uidLines = lines.filter((l) => l.startsWith('uid:'));
    if (pubKeys.length === 0 && uidLines.length === 0) {
      return {
        check: {
          source: srcName,
          status: 'not_found',
          summary: lang === 'tr' ? 'PGP anahtarı bulunamadı.' : 'No PGP key found.',
          details: {},
        },
        uids: [],
        altEmails: [],
      };
    }

    const decodedUids: string[] = [];
    const altEmails = new Set<string>();
    const emailRe = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
    for (const line of uidLines.slice(0, 12)) {
      const rawUid = line.split(':')[1] || '';
      let uidStr = rawUid;
      try {
        uidStr = decodeURIComponent(rawUid);
      } catch {
        uidStr = rawUid;
      }
      if (uidStr && !decodedUids.includes(uidStr)) {
        decodedUids.push(uidStr);
        const matches = uidStr.match(emailRe);
        if (matches) {
          matches.forEach((m) => altEmails.add(m.toLowerCase()));
        }
      }
    }

    const fingerprints = pubKeys
      .slice(0, 5)
      .map((l) => {
        const parts = l.split(':');
        const fp = parts[1] || '';
        const ts = Number(parts[4] || 0);
        const dt = ts > 0 ? new Date(ts * 1000).toISOString().slice(0, 10) : '';
        return dt ? `${fp} (${dt})` : fp;
      })
      .filter(Boolean);

    return {
      check: {
        source: srcName,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${pubKeys.length} PGP anahtarı ve ${decodedUids.length} kimlik (UID) etiketi bulundu.`
            : `Found ${pubKeys.length} PGP key(s) and ${decodedUids.length} UID label(s).`,
        details: {
          ...(decodedUids.length > 0 ? { [lang === 'tr' ? 'kimlikEtiketleri' : 'pgpUids']: decodedUids } : {}),
          ...(fingerprints.length > 0 ? { [lang === 'tr' ? 'anahtarlar' : 'keys']: fingerprints } : {}),
        },
      },
      uids: decodedUids,
      altEmails: Array.from(altEmails),
    };
  } catch {
    return {
      check: {
        source: srcName,
        status: 'error',
        summary: lang === 'tr' ? 'Ubuntu PGP sunucusu yanıt vermedi.' : 'Ubuntu PGP server timed out.',
        details: {},
      },
      uids: [],
      altEmails: [],
    };
  }
}

interface GravatarRes {
  check: EmailOsintSourceResult;
  names: string[];
  usernames: string[];
  emails: string[];
  locations: string[];
}

async function checkGravatar(email: string, lang: Lang): Promise<GravatarRes> {
  const srcName = lang === 'tr' ? 'Gravatar Genel Profili' : 'Gravatar Public Profile';
  const hash = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
  const md5 = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  const empty: GravatarRes = {
    check: {
      source: srcName,
      status: 'not_found',
      summary:
        lang === 'tr'
          ? 'Bu e-posta ile eşleşen Gravatar profili bulunamadı.'
          : 'No public Gravatar profile matched this email.',
      details: { sha256: hash, md5 },
    },
    names: [],
    usernames: [],
    emails: [],
    locations: [],
  };
  try {
    const res = await fetchWithTimeout(`https://en.gravatar.com/${hash}.json`, {}, 4200);
    if (res.status === 404) return empty;
    if (!res.ok) {
      return {
        ...empty,
        check: { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: { sha256: hash } },
      };
    }
    const data = (await res.json()) as {
      entry?: Array<{
        displayName?: string;
        preferredUsername?: string;
        profileUrl?: string;
        currentLocation?: string;
        aboutMe?: string;
        emails?: Array<{ value?: string }>;
        phoneNumbers?: Array<{ value?: string; type?: string }>;
        accounts?: Array<{ shortname?: string; url?: string; username?: string }>;
        urls?: Array<{ title?: string; value?: string }>;
      }>;
    };
    const entry = data.entry?.[0];
    if (!entry) {
      return {
        ...empty,
        check: {
          source: srcName,
          status: 'not_found',
          summary: lang === 'tr' ? 'Gravatar profili boş döndü.' : 'Gravatar profile empty.',
          details: { sha256: hash, md5 },
        },
      };
    }

    const names = entry.displayName ? [entry.displayName] : [];
    const usernames = [
      ...(entry.preferredUsername ? [entry.preferredUsername] : []),
      ...((entry.accounts || []).map((a) => a.username).filter(Boolean) as string[]),
    ];
    const emails = (entry.emails || []).map((e) => e.value).filter(Boolean) as string[];
    const locations = entry.currentLocation ? [entry.currentLocation] : [];

    const details: Record<string, string | string[]> = {
      [lang === 'tr' ? 'gorunenAd' : 'displayName']: entry.displayName || '—',
      [lang === 'tr' ? 'kullaniciAdi' : 'username']: entry.preferredUsername || '—',
      profilUrl: entry.profileUrl || `https://gravatar.com/${hash}`,
    };
    if (entry.currentLocation) {
      details[lang === 'tr' ? 'konumAdres' : 'location'] = entry.currentLocation;
    }
    if (entry.aboutMe) {
      details[lang === 'tr' ? 'hakkimda' : 'bio'] = entry.aboutMe;
    }
    if (emails.length > 0) {
      details[lang === 'tr' ? 'epostalar' : 'emails'] = emails;
    }
    if (Array.isArray(entry.phoneNumbers) && entry.phoneNumbers.length > 0) {
      const phones = entry.phoneNumbers.map((p) => (p.type ? `${p.type}: ${p.value}` : p.value || '')).filter(Boolean);
      if (phones.length > 0) details[lang === 'tr' ? 'telefonlar' : 'phones'] = phones;
    }
    if (Array.isArray(entry.accounts) && entry.accounts.length > 0) {
      const accs = entry.accounts.map((a) => `${a.shortname || 'web'}: ${a.url || a.username || ''}`).filter(Boolean);
      if (accs.length > 0) details[lang === 'tr' ? 'sosyalHesaplar' : 'linkedAccounts'] = accs;
    }
    if (Array.isArray(entry.urls) && entry.urls.length > 0) {
      const urls = entry.urls.map((u) => (u.title ? `${u.title}: ${u.value}` : u.value || '')).filter(Boolean);
      if (urls.length > 0) details[lang === 'tr' ? 'baglantilar' : 'urls'] = urls;
    }

    return {
      check: {
        source: srcName,
        status: 'found',
        summary:
          lang === 'tr'
            ? `Gravatar profili tespit edildi: ${entry.displayName || entry.preferredUsername || 'Profil Mevcut'}`
            : `Gravatar profile found: ${entry.displayName || entry.preferredUsername || 'Available'}`,
        details,
      },
      names,
      usernames,
      emails,
      locations,
    };
  } catch {
    return {
      ...empty,
      check: {
        source: srcName,
        status: 'error',
        summary: lang === 'tr' ? 'Gravatar API servisine ulaşılamadı.' : 'Could not reach Gravatar API.',
        details: { sha256: hash },
      },
    };
  }
}

interface GitHubRes {
  check: EmailOsintSourceResult;
  names: string[];
  usernames: string[];
  emails: string[];
  locations: string[];
}

async function checkGitHub(email: string, lang: Lang): Promise<GitHubRes> {
  const srcName = lang === 'tr' ? 'GitHub Genel Arama' : 'GitHub Public Search';
  const empty: GitHubRes = {
    check: {
      source: srcName,
      status: 'not_found',
      summary:
        lang === 'tr'
          ? 'Herkese açık GitHub profillerinde veya commit kayıtlarında bu e-posta eşleşmedi.'
          : 'No public GitHub profiles or commits matched this email.',
      details: {},
    },
    names: [],
    usernames: [],
    emails: [],
    locations: [],
  };
  try {
    const [usersRes, commitsRes] = await Promise.all([
      fetchWithTimeout(`https://api.github.com/search/users?q=${encodeURIComponent(`${email} in:email`)}`, {}, 4500),
      fetchWithTimeout(
        `https://api.github.com/search/commits?q=${encodeURIComponent(`author-email:${email}`)}&per_page=5`,
        { Accept: 'application/vnd.github+json' },
        4500,
      ).catch(() => null),
    ]);

    if (!usersRes.ok) {
      return {
        ...empty,
        check: { source: srcName, status: 'error', summary: `HTTP ${usersRes.status}`, details: {} },
      };
    }

    const userData = (await usersRes.json()) as {
      total_count?: number;
      items?: Array<{ login: string; html_url: string }>;
    };

    const commitData = commitsRes?.ok
      ? ((await commitsRes.json()) as {
          total_count?: number;
          items?: Array<{
            html_url?: string;
            repository?: { full_name?: string };
            commit?: { author?: { name?: string; email?: string } };
          }>;
        })
      : null;

    const userItems = userData.items || [];
    const commitItems = commitData?.items || [];

    if ((!userData.total_count || userItems.length === 0) && (!commitData?.total_count || commitItems.length === 0)) {
      return empty;
    }

    const fullProfiles = await Promise.all(
      userItems.slice(0, 5).map(async (u) => {
        try {
          const profRes = await fetchWithTimeout(
            `https://api.github.com/users/${encodeURIComponent(u.login)}`,
            {},
            3500,
          );
          if (!profRes.ok) return { login: u.login, html_url: u.html_url };
          return (await profRes.json()) as {
            login: string;
            html_url: string;
            name?: string | null;
            email?: string | null;
            location?: string | null;
            company?: string | null;
            blog?: string | null;
            bio?: string | null;
            twitter_username?: string | null;
            public_repos?: number;
          };
        } catch {
          return { login: u.login, html_url: u.html_url };
        }
      }),
    );

    const names: string[] = [];
    const usernames: string[] = [];
    const emails: string[] = [];
    const locations: string[] = [];

    const formattedProfiles = fullProfiles.map((p) => {
      usernames.push(p.login);
      const fields: string[] = [`${p.login} (${p.html_url})`];
      if ('name' in p && p.name) {
        names.push(p.name);
        fields.push(`${lang === 'tr' ? 'Ad' : 'Name'}: ${p.name}`);
      }
      if ('email' in p && p.email) {
        emails.push(p.email.toLowerCase());
        fields.push(`${lang === 'tr' ? 'Açık E-posta' : 'Public Email'}: ${p.email}`);
      }
      if ('location' in p && p.location) {
        locations.push(p.location);
        fields.push(`${lang === 'tr' ? 'Konum/Adres' : 'Location'}: ${p.location}`);
      }
      if ('company' in p && p.company) fields.push(`${lang === 'tr' ? 'Şirket' : 'Company'}: ${p.company}`);
      if ('blog' in p && p.blog) fields.push(`Web: ${p.blog}`);
      if ('twitter_username' in p && p.twitter_username) {
        usernames.push(p.twitter_username);
        fields.push(`X/Twitter: @${p.twitter_username}`);
      }
      if ('bio' in p && p.bio) fields.push(`Bio: ${p.bio}`);
      return fields.join(' | ');
    });

    for (const c of commitItems) {
      if (c.commit?.author?.name) names.push(c.commit.author.name);
      if (c.commit?.author?.email) emails.push(c.commit.author.email.toLowerCase());
    }

    const details: Record<string, string | string[]> = {};
    if (formattedProfiles.length > 0) {
      details[lang === 'tr' ? 'profiller' : 'profiles'] = formattedProfiles;
    }
    if (commitItems.length > 0) {
      details[lang === 'tr' ? 'acikCommitler' : 'publicCommits'] = commitItems.slice(0, 5).map((c) => {
        const repo = c.repository?.full_name || 'repo';
        const author = c.commit?.author?.name || '';
        const commitEmail = c.commit?.author?.email || '';
        return `${repo} — ${author} <${commitEmail}> (${c.html_url || ''})`;
      });
    }

    const totalMatched = Math.max(userData.total_count || 0, commitData?.total_count || 0);
    return {
      check: {
        source: srcName,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${totalMatched} açık GitHub eşleşmesi bulundu${userItems[0] ? ` (${userItems[0].login})` : ''}.`
            : `Matched ${totalMatched} public GitHub result(s)${userItems[0] ? ` (${userItems[0].login})` : ''}.`,
        details,
      },
      names,
      usernames,
      emails,
      locations,
    };
  } catch {
    return {
      ...empty,
      check: {
        source: srcName,
        status: 'error',
        summary: lang === 'tr' ? 'GitHub API zaman aşımı.' : 'GitHub API timed out.',
        details: {},
      },
    };
  }
}

async function checkGitLab(
  email: string,
  lang: Lang,
): Promise<{ check: EmailOsintSourceResult; names: string[]; usernames: string[] }> {
  const srcName = lang === 'tr' ? 'GitLab Genel Profiller' : 'GitLab Public Profiles';
  try {
    const res = await fetchWithTimeout(
      `https://gitlab.com/api/v4/users?search=${encodeURIComponent(email)}&per_page=5`,
      {},
      4200,
    );
    if (!res.ok) {
      return { check: { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} }, names: [], usernames: [] };
    }
    const items = (await res.json()) as Array<{
      username?: string;
      name?: string;
      state?: string;
      web_url?: string;
    }>;
    if (!Array.isArray(items) || items.length === 0) {
      return {
        check: {
          source: srcName,
          status: 'not_found',
          summary: lang === 'tr' ? 'GitLab genel profillerinde eşleşme bulunamadı.' : 'No public GitLab profiles matched.',
          details: {},
        },
        names: [],
        usernames: [],
      };
    }
    const names = items.map((i) => i.name).filter(Boolean) as string[];
    const usernames = items.map((i) => i.username).filter(Boolean) as string[];
    const formatted = items.map((i) => `${i.username || '—'} (${i.name || '—'}) — ${i.web_url || ''}`);
    return {
      check: {
        source: srcName,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${items.length} açık GitLab profili bulundu.`
            : `Matched ${items.length} public GitLab profile(s).`,
        details: {
          [lang === 'tr' ? 'profiller' : 'profiles']: formatted,
        },
      },
      names,
      usernames,
    };
  } catch {
    return {
      check: { source: srcName, status: 'error', summary: lang === 'tr' ? 'GitLab API zaman aşımı.' : 'GitLab API timed out.', details: {} },
      names: [],
      usernames: [],
    };
  }
}

async function checkNpmPublisher(
  email: string,
  lang: Lang,
): Promise<{ check: EmailOsintSourceResult; usernames: string[] }> {
  const srcName = 'npm Public Registry';
  try {
    const res = await fetchWithTimeout(
      `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(email)}&size=10`,
      {},
      4200,
    );
    if (!res.ok) {
      return { check: { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} }, usernames: [] };
    }
    const data = (await res.json()) as {
      objects?: Array<{
        package?: {
          name?: string;
          version?: string;
          links?: { npm?: string };
          publisher?: { username?: string; email?: string };
          maintainers?: Array<{ username?: string; email?: string }>;
        };
      }>;
    };
    const exactEmail = email.trim().toLowerCase();
    const matchedPkgs = (data.objects || []).filter((obj) => {
      const p = obj.package;
      if (!p) return false;
      if (p.publisher?.email?.toLowerCase() === exactEmail) return true;
      return Boolean(p.maintainers?.some((m) => m.email?.toLowerCase() === exactEmail));
    });

    if (matchedPkgs.length === 0) {
      return {
        check: {
          source: srcName,
          status: 'not_found',
          summary: lang === 'tr' ? 'npm kayıtlarında yayıncı eşleşmesi yok.' : 'No npm package publisher matched.',
          details: {},
        },
        usernames: [],
      };
    }

    const usernames = new Set<string>();
    const pkgList = matchedPkgs.slice(0, 6).map((obj) => {
      const p = obj.package!;
      if (p.publisher?.email?.toLowerCase() === exactEmail && p.publisher.username) {
        usernames.add(p.publisher.username);
      }
      for (const m of p.maintainers || []) {
        if (m.email?.toLowerCase() === exactEmail && m.username) usernames.add(m.username);
      }
      return `${p.name}@${p.version || 'latest'}${p.links?.npm ? ` (${p.links.npm})` : ''}`;
    });

    return {
      check: {
        source: srcName,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${matchedPkgs.length} açık npm paketinde geliştirici e-postası eşleşti.`
            : `Email matched maintainer/publisher on ${matchedPkgs.length} npm package(s).`,
        details: {
          ...(usernames.size > 0 ? { [lang === 'tr' ? 'gelistiriciAdlari' : 'npmUsernames']: Array.from(usernames) } : {}),
          [lang === 'tr' ? 'paketler' : 'packages']: pkgList,
        },
      },
      usernames: Array.from(usernames),
    };
  } catch {
    return {
      check: { source: srcName, status: 'error', summary: lang === 'tr' ? 'npm servisine ulaşılamadı.' : 'Could not reach npm registry.', details: {} },
      usernames: [],
    };
  }
}

async function checkMicrosoftRealm(email: string, domain: string): Promise<string | null> {
  if (!domain || domain.endsWith('.test') || domain.endsWith('.invalid') || domain.endsWith('.local')) {
    return null;
  }
  try {
    const res = await fetchWithTimeout(
      `https://login.microsoftonline.com/getuserrealm.srf?login=${encodeURIComponent(email)}&json=1`,
      {},
      3200,
    );
    if (!res.ok) return null;
    const data = (await res.json()) as {
      NameSpaceType?: string;
      FederationBrandName?: string;
    };
    if (data.NameSpaceType && data.NameSpaceType !== 'Unknown') {
      return data.FederationBrandName
        ? `${data.NameSpaceType} (${data.FederationBrandName})`
        : data.NameSpaceType;
    }
    return null;
  } catch {
    return null;
  }
}

async function checkRdap(domain: string): Promise<{
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
} | null> {
  if (!domain || domain.endsWith('.test') || domain.endsWith('.invalid') || domain.endsWith('.local')) {
    return null;
  }
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {}, 4000);
    if (!res.ok) return null;
    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };
    const created = data.events?.find((e) => e.eventAction === 'registration')?.eventDate || null;
    const expiry = data.events?.find((e) => e.eventAction === 'expiration')?.eventDate || null;
    let registrar: string | null = null;
    const regEntity = data.entities?.find((en) => en.roles?.includes('registrar'));
    if (regEntity && Array.isArray(regEntity.vcardArray) && Array.isArray(regEntity.vcardArray[1])) {
      const fnEntry = (regEntity.vcardArray[1] as unknown[][]).find((row) => row[0] === 'fn');
      if (fnEntry && typeof fnEntry[3] === 'string') {
        registrar = fnEntry[3];
      }
    }
    return { registrar, createdDate: created, expiryDate: expiry };
  } catch {
    return null;
  }
}

interface CachedExternalOsint {
  expiresAt: number;
  isDisposable: boolean;
  mailProvider: string;
  mxRecords: { exchange: string; priority: number }[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  bimiRecord: string | null;
  mtaStsRecord: string | null;
  microsoftTenant: string | null;
  rdap: { registrar: string | null; createdDate: string | null; expiryDate: string | null } | null;
  externalChecks: EmailOsintSourceResult[];
  discoveredNames: string[];
  discoveredUsernames: string[];
  discoveredEmails: string[];
  discoveredLocations: string[];
  pivotLinks: { label: string; url: string }[];
}

const EXTERNAL_CACHE_TTL_MS = 60_000;
const MAX_EXTERNAL_CACHE = 500;
const externalOsintCache = new Map<string, CachedExternalOsint>();
const inflightExternalOsint = new Map<string, Promise<CachedExternalOsint>>();

async function resolveExternalOsintWithCoalescing(
  email: string,
  domain: string,
  lang: Lang,
): Promise<CachedExternalOsint> {
  const cacheKey = `${email}:${lang}`;
  const cached = externalOsintCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached;
  }

  const inflight = inflightExternalOsint.get(cacheKey);
  if (inflight) {
    return inflight;
  }

  const task = (async (): Promise<CachedExternalOsint> => {
    const [
      mxRes,
      txtRes,
      dmarcRes,
      bimiRes,
      mtaStsRes,
      disposableRes,
      rdap,
      microsoftTenant,
      xon,
      leakCheck,
      hudsonRock,
      comb,
      protonPgp,
      openPgp,
      ubuntuPgp,
      gravatar,
      github,
      gitlab,
      npmRes,
    ] = await Promise.all([
      dns.resolveMx(domain).catch(() => []),
      dns.resolveTxt(domain).catch(() => []),
      dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
      dns.resolveTxt(`default._bimi.${domain}`).catch(() => []),
      dns.resolveTxt(`_mta-sts.${domain}`).catch(() => []),
      checkDisposableEmail(email).catch(() => null),
      checkRdap(domain),
      checkMicrosoftRealm(email, domain),
      checkXposedOrNot(email, lang),
      checkLeakCheckPublic(email, lang),
      checkHudsonRock(email, lang),
      checkProxyNovaComb(email, lang),
      checkProtonPgp(email, lang),
      checkOpenPgp(email, lang),
      checkUbuntuKeyserver(email, lang),
      checkGravatar(email, lang),
      checkGitHub(email, lang),
      checkGitLab(email, lang),
      checkNpmPublisher(email, lang),
    ]);

    const isDisposable = Boolean(disposableRes?.isDisposable);
    const mxRecords = [...mxRes]
      .sort((a, b) => a.priority - b.priority)
      .map((m) => ({ exchange: m.exchange, priority: m.priority }));

    const flatTxt = txtRes.map((chunks) => chunks.join(''));
    const spfRecord = flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null;

    const flatDmarc = dmarcRes.map((chunks) => chunks.join(''));
    const dmarcRecord = flatDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;

    const bimiRecord = bimiRes.map((c) => c.join('')).find((t) => t.toLowerCase().startsWith('v=bimi1')) || null;
    const mtaStsRecord = mtaStsRes.map((c) => c.join('')).find((t) => t.toLowerCase().startsWith('v=stsv1')) || null;

    const mailProvider = detectMailProvider(
      mxRecords.map((m) => m.exchange),
      domain,
      lang,
    );

    const discoveredNames = Array.from(
      new Set([...gravatar.names, ...github.names, ...gitlab.names].map((x) => x.trim()).filter(Boolean)),
    );
    const discoveredUsernames = Array.from(
      new Set(
        [...gravatar.usernames, ...github.usernames, ...gitlab.usernames, ...npmRes.usernames]
          .map((x) => x.trim())
          .filter(Boolean),
      ),
    );
    const discoveredEmails = Array.from(
      new Set(
        [...ubuntuPgp.altEmails, ...gravatar.emails, ...github.emails]
          .map((x) => x.trim().toLowerCase())
          .filter((e) => e && e !== email),
      ),
    );
    const discoveredLocations = Array.from(
      new Set([...gravatar.locations, ...github.locations].map((x) => x.trim()).filter(Boolean)),
    );

    const encodedEmail = encodeURIComponent(email);
    const encodedDomain = encodeURIComponent(domain);

    const pivotLinks = [
      { label: 'QuadNet OSINT', url: `https://quadnet.xyz/?q=${encodedEmail}` },
      { label: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encodedEmail}` },
      { label: 'LeakCheck', url: `https://leakcheck.io/` },
      { label: 'Epieos OSINT', url: `https://epieos.com/?q=${encodedEmail}` },
      { label: 'Hudson Rock Cavalier', url: `https://www.hudsonrock.com/free-tools` },
      { label: 'BreachDirectory', url: `https://breachdirectory.org/` },
      { label: 'IntelX Search', url: `https://intelx.io/?s=${encodedEmail}` },
      { label: 'DeHashed', url: `https://dehashed.com/search?query=${encodedEmail}` },
      { label: 'Hunter.io Domain', url: `https://hunter.io/search/${encodedDomain}` },
      { label: 'MXToolbox DNS/MX', url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodedDomain}` },
    ];

    const entry: CachedExternalOsint = {
      expiresAt: Date.now() + EXTERNAL_CACHE_TTL_MS,
      isDisposable,
      mailProvider,
      mxRecords,
      spfRecord,
      dmarcRecord,
      bimiRecord,
      mtaStsRecord,
      microsoftTenant,
      rdap,
      externalChecks: [
        xon,
        leakCheck,
        hudsonRock,
        comb,
        gravatar.check,
        github.check,
        gitlab.check,
        npmRes.check,
        protonPgp,
        openPgp,
        ubuntuPgp.check,
      ],
      discoveredNames,
      discoveredUsernames,
      discoveredEmails,
      discoveredLocations,
      pivotLinks,
    };

    if (externalOsintCache.size >= MAX_EXTERNAL_CACHE) {
      const oldestKey = externalOsintCache.keys().next().value;
      if (oldestKey !== undefined) externalOsintCache.delete(oldestKey);
    }
    externalOsintCache.set(cacheKey, entry);
    return entry;
  })();

  inflightExternalOsint.set(cacheKey, task);
  try {
    return await task;
  } finally {
    if (inflightExternalOsint.get(cacheKey) === task) {
      inflightExternalOsint.delete(cacheKey);
    }
  }
}

function summarizeLocalOsintSignals(
  localMatches: IntelRecord[],
): EmailOsintIdentitySummary['localExposedSignals'] & { usernames: string[] } {
  const passwords = new Set<string>();
  const tokens = new Set<string>();
  const ips = new Set<string>();
  const phones = new Set<string>();
  const discordIds = new Set<string>();
  const hwids = new Set<string>();
  const usernames = new Set<string>();

  for (const r of localMatches) {
    if (r.username.trim()) usernames.add(r.username.trim());
    if (r.ip.trim()) ips.add(r.ip.trim());
    for (const ip of extractRecordIps(r)) ips.add(ip);
    if (r.phone.trim() && !isTimestampLikeValue(r.phone)) phones.add(r.phone.trim());
    for (const ph of extractRecordPhones(r)) phones.add(ph);
    for (const sf of extractRecordSnowflakes(r)) discordIds.add(sf);
    for (const [k, rawVal] of Object.entries(r.extra || {})) {
      const cleanKey = k.trim().toLowerCase();
      const val = String(rawVal || '').trim();
      if (!val) continue;
      if (/^(password|pass|pw|pwd|sifre|parola)$/i.test(cleanKey)) {
        passwords.add(val);
      } else if (/^(token|auth_token|access_token|secret)$/i.test(cleanKey)) {
        tokens.add(val);
      } else if (/^(hwid|hw_id|guid|machine_id)$/i.test(cleanKey) && val.length >= 4) {
        hwids.add(val);
      }
    }
    const existingHwidLower = new Set(Array.from(hwids).map((x) => x.toLowerCase()));
    for (const eid of extractRecordExtraIdentifiers(r)) {
      if (eid.startsWith('hwid:')) {
        const val = eid.slice(5);
        if (!existingHwidLower.has(val.toLowerCase())) {
          hwids.add(val);
          existingHwidLower.add(val.toLowerCase());
        }
      }
    }
  }

  return {
    passwords: Array.from(passwords).slice(0, 25),
    tokens: Array.from(tokens).slice(0, 15),
    ips: Array.from(ips).slice(0, 30),
    phones: Array.from(phones).slice(0, 30),
    discordIds: Array.from(discordIds).slice(0, 30),
    hwids: Array.from(hwids).slice(0, 20),
    usernames: Array.from(usernames).slice(0, 40),
  };
}

export function mergeLocalSignalsIntoIdentitySummary(
  identitySummary: EmailOsintIdentitySummary,
  localMatches: IntelRecord[],
): EmailOsintIdentitySummary {
  const localSignals = summarizeLocalOsintSignals(localMatches);
  return {
    ...identitySummary,
    discoveredUsernames: Array.from(
      new Set([...identitySummary.discoveredUsernames, ...localSignals.usernames]),
    ).slice(0, 50),
    localExposedSignals: {
      passwords: localSignals.passwords,
      tokens: localSignals.tokens,
      ips: localSignals.ips,
      phones: localSignals.phones,
      discordIds: localSignals.discordIds,
      hwids: localSignals.hwids,
    },
  };
}

export async function runEmailOsint(
  rawEmail: string,
  localRecords: IntelRecord[],
  lang: Lang = 'tr',
  prebuiltIndex?: SearchIndex,
): Promise<EmailOsintReport> {
  const started = performance.now();
  const email = rawEmail.trim().toLowerCase();
  const isValidSyntax = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  const domain = email.includes('@') ? email.split('@')[1] || '' : '';
  const { canonical, isRoleAddress } = computeCanonicalEmail(email);

  const localMatchesMap = new Map<string, IntelRecord>();
  const primarySearch = email ? searchRecords(localRecords, email, 'email', true, localRecords, prebuiltIndex) : null;
  if (primarySearch) {
    for (const r of [...primarySearch.primaryMatches, ...primarySearch.relatedMatches]) {
      localMatchesMap.set(r.id, r);
    }
  }
  if (canonical && canonical !== email) {
    const canonSearch = searchRecords(localRecords, canonical, 'email', true, localRecords, prebuiltIndex);
    for (const r of [...canonSearch.primaryMatches, ...canonSearch.relatedMatches]) {
      localMatchesMap.set(r.id, r);
    }
  }
  const localMatches = Array.from(localMatchesMap.values());

  if (!isValidSyntax || !domain) {
    return {
      email,
      domain,
      isValidSyntax: false,
      isDisposable: false,
      mailProvider: lang === 'tr' ? 'Geçersiz E-posta Biçimi' : 'Invalid Email Format',
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      rdap: null,
      externalChecks: [],
      localMatches,
      pivotLinks: [],
      checkedAt: new Date().toISOString(),
      durationMs: Number((performance.now() - started).toFixed(2)),
    };
  }

  const ext = await resolveExternalOsintWithCoalescing(email, domain, lang);
  const baseSummary: EmailOsintIdentitySummary = {
    canonicalEmail: canonical,
    isRoleAddress,
    spoofingRisk: evaluateSpoofingRisk(ext.spfRecord, ext.dmarcRecord),
    bimiRecord: ext.bimiRecord,
    mtaStsRecord: ext.mtaStsRecord,
    microsoftTenant: ext.microsoftTenant,
    discoveredNames: ext.discoveredNames,
    discoveredUsernames: ext.discoveredUsernames,
    discoveredEmails: ext.discoveredEmails,
    discoveredLocations: ext.discoveredLocations,
    localExposedSignals: {
      passwords: [],
      tokens: [],
      ips: [],
      phones: [],
      discordIds: [],
      hwids: [],
    },
  };
  const identitySummary = mergeLocalSignalsIntoIdentitySummary(baseSummary, localMatches);

  return {
    email,
    domain,
    isValidSyntax: true,
    isDisposable: ext.isDisposable,
    mailProvider: ext.mailProvider,
    mxRecords: ext.mxRecords,
    spfRecord: ext.spfRecord,
    dmarcRecord: ext.dmarcRecord,
    rdap: ext.rdap,
    identitySummary,
    externalChecks: ext.externalChecks,
    localMatches,
    pivotLinks: ext.pivotLinks,
    checkedAt: new Date().toISOString(),
    durationMs: Math.max(1, Number((performance.now() - started).toFixed(2))),
  };
}

