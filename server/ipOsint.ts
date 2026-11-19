import dns from 'node:dns/promises';
import net from 'node:net';
import type { IpOsintReport, IpOsintSourceResult } from '../src/types/intel.ts';

type Lang = 'tr' | 'en';

export function normalizeIpInput(raw: string): string {
  let trimmed = String(raw || '').trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  const v4PortMatch = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if (v4PortMatch && net.isIPv4(v4PortMatch[1])) {
    return v4PortMatch[1];
  }
  return trimmed;
}

export function isValidIpAddress(raw: string): { valid: boolean; ip: string; version: 4 | 6 | 0 } {
  const ip = normalizeIpInput(raw);
  const ver = net.isIP(ip);
  if (ver === 4) return { valid: true, ip, version: 4 };
  if (ver === 6) return { valid: true, ip: ip.toLowerCase(), version: 6 };
  return { valid: false, ip, version: 0 };
}

function classifyIpv4Scope(ip: string, lang: Lang): { isPublic: boolean; note: string } {
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 127) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Geri Döngü / Loopback (RFC 1122)' : 'Loopback Address (RFC 1122)',
    };
  }
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Özel Yerel Ağ / LAN (RFC 1918)' : 'Private Local Network / LAN (RFC 1918)',
    };
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Operatör Paylaşımlı Ağ / CGNAT (RFC 6598)' : 'Carrier-Grade NAT / CGNAT (RFC 6598)',
    };
  }
  if (a === 169 && b === 254) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Bağlantı Yerel / Link-Local (RFC 3927)' : 'Link-Local / APIPA (RFC 3927)',
    };
  }
  if (a === 0 || a >= 224) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Ayrılmış / Çoklu Yayın (Reserved / Multicast)' : 'Reserved / Multicast Range',
    };
  }
  return {
    isPublic: true,
    note: lang === 'tr' ? 'Genel Yönlendirilebilir IPv4' : 'Public Routable IPv4',
  };
}

function classifyIpv6Scope(ip: string, lang: Lang): { isPublic: boolean; note: string } {
  const lower = ip.toLowerCase();
  const mappedMatch = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mappedMatch && net.isIPv4(mappedMatch[1])) {
    return classifyIpv4Scope(mappedMatch[1], lang);
  }
  if (lower === '::1' || lower === '::' || lower === '0:0:0:0:0:0:0:1' || lower === '0:0:0:0:0:0:0:0') {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Geri Döngü veya Belirtilmemiş IPv6' : 'Loopback or Unspecified IPv6',
    };
  }
  const firstHextet = lower.split(':')[0] || '';
  if (/^fe[89ab][0-9a-f]?$/i.test(firstHextet)) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Bağlantı Yerel IPv6 (fe80::/10)' : 'Link-Local IPv6 (fe80::/10)',
    };
  }
  if (/^f[cd][0-9a-f]{2}$/i.test(firstHextet)) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Benzersiz Yerel IPv6 / ULA (fc00::/7)' : 'Unique Local IPv6 / ULA (fc00::/7)',
    };
  }
  if (/^ff[0-9a-f]{2}$/i.test(firstHextet)) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Çoklu Yayın IPv6 (ff00::/8)' : 'Multicast IPv6 (ff00::/8)',
    };
  }
  if (lower.startsWith('2001:db8:')) {
    return {
      isPublic: false,
      note: lang === 'tr' ? 'Dokümantasyon Ağı IPv6 (RFC 3849)' : 'Documentation IPv6 Prefix (RFC 3849)',
    };
  }
  return {
    isPublic: true,
    note: lang === 'tr' ? 'Genel Yönlendirilebilir IPv6' : 'Public Routable IPv6',
  };
}

export function classifyIpScope(ip: string, version: 4 | 6, lang: Lang): { isPublic: boolean; note: string } {
  return version === 4 ? classifyIpv4Scope(ip, lang) : classifyIpv6Scope(ip, lang);
}

async function fetchWithTimeout(url: string, timeoutMs = 4500): Promise<Response> {
  return fetch(url, {
    headers: {
      'User-Agent': 'Sentarika-Archive-IP-OSINT/1.0',
      Accept: 'application/json, text/plain;q=0.9',
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
}

function inferRirFromRdap(data: { port43?: string; links?: Array<{ href?: string }> }): string | null {
  const combined = [
    data.port43 || '',
    ...(Array.isArray(data.links) ? data.links.map((l) => l.href || '') : []),
  ]
    .join(' ')
    .toLowerCase();
  if (combined.includes('ripe')) return 'RIPE NCC';
  if (combined.includes('arin')) return 'ARIN';
  if (combined.includes('apnic')) return 'APNIC';
  if (combined.includes('lacnic')) return 'LACNIC';
  if (combined.includes('afrinic')) return 'AFRINIC';
  return null;
}

function extractRdapAbuseContacts(
  entities: Array<{ roles?: string[]; vcardArray?: unknown[]; entities?: unknown[] }> | undefined,
): string[] {
  const out = new Set<string>();
  const walk = (list: unknown[]) => {
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      const ent = raw as { roles?: string[]; vcardArray?: unknown[]; entities?: unknown[] };
      const isAbuse = Array.isArray(ent.roles) && ent.roles.some((r) => r === 'abuse' || r === 'technical' || r === 'noc');
      if (isAbuse && Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1])) {
        for (const row of ent.vcardArray[1] as unknown[]) {
          if (Array.isArray(row) && (row[0] === 'email' || row[0] === 'tel') && typeof row[3] === 'string') {
            const val = row[3].trim();
            if (val) out.add(val);
          }
        }
      }
      if (Array.isArray(ent.entities)) {
        walk(ent.entities);
      }
    }
  };
  if (Array.isArray(entities)) walk(entities);
  return Array.from(out).slice(0, 6);
}

interface RdapLookupResult {
  rdap: IpOsintReport['rdap'];
  check: IpOsintSourceResult;
}

async function fetchRipeStatWhoisFallback(ip: string, lang: Lang): Promise<RdapLookupResult | null> {
  const source = lang === 'tr' ? 'WHOIS / RDAP Resmi Kayıt (RIR)' : 'WHOIS / RDAP Official Registry (RIR)';
  try {
    const res = await fetchWithTimeout(
      `https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`,
      4500,
    );
    if (!res.ok) return null;
    const json = (await res.json()) as {
      data?: {
        records?: Array<Array<{ key?: string; value?: string }>>;
        authorities?: string[];
      };
    };
    const records = Array.isArray(json.data?.records) ? json.data!.records : [];
    if (records.length === 0) return null;

    const flat = records.flat();
    const pick = (...keys: string[]): string | null => {
      for (const k of keys) {
        const hit = flat.find((f) => f.key?.toLowerCase() === k.toLowerCase() && f.value?.trim());
        if (hit?.value) return hit.value.trim();
      }
      return null;
    };

    const abuseSet = new Set<string>();
    for (const f of flat) {
      const k = (f.key || '').toLowerCase();
      if ((k.includes('abuse') || k === 'e-mail' || k === 'orgabuseemail' || k === 'orgtechemail') && f.value?.trim()) {
        abuseSet.add(f.value.trim());
      }
    }

    const authorities = Array.isArray(json.data?.authorities)
      ? json.data!.authorities.map((a) => a.toUpperCase()).join(', ')
      : null;
    const name = pick('netname', 'NetName', 'owner', 'Organization', 'OrgName', 'descr');
    const handle = pick('NetHandle', 'nic-hdl', 'origin', 'OriginAS');
    const cidr = pick('CIDR', 'inetnum', 'inet6num', 'route', 'route6');
    const country = pick('country', 'Country');
    const registeredDate = pick('RegDate', 'created');
    const lastChangedDate = pick('Updated', 'last-modified');
    const abuseContacts = Array.from(abuseSet).slice(0, 6);

    const details: Record<string, string | string[]> = {};
    if (authorities) details.RIR = authorities;
    if (name) details[lang === 'tr' ? 'agAdi' : 'netname'] = name;
    if (cidr) details.CIDR = cidr;
    if (handle) details.handle = handle;
    if (country) details[lang === 'tr' ? 'ulke' : 'country'] = country;
    if (abuseContacts.length > 0) details[lang === 'tr' ? 'ihlalIletisim' : 'abuseContact'] = abuseContacts;
    if (registeredDate) details[lang === 'tr' ? 'kayitTarihi' : 'registered'] = registeredDate.slice(0, 10);

    return {
      rdap: {
        handle,
        name,
        cidr,
        rir: authorities,
        country,
        type: null,
        status: [],
        abuseContacts,
        registeredDate,
        lastChangedDate,
      },
      check: {
        source,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${authorities || 'RIR'} resmi kaydı doğrulandı${name ? `: ${name}` : ''}.`
            : `Verified via ${authorities || 'RIR'}${name ? `: ${name}` : ''}.`,
        details,
      },
    };
  } catch {
    return null;
  }
}

async function checkIpRdap(ip: string, lang: Lang): Promise<RdapLookupResult> {
  const source = lang === 'tr' ? 'RDAP Resmi Kayıt (RIR)' : 'RDAP Official Registry (RIR)';
  try {
    const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SentarikaArchive/1.0)',
        Accept: 'application/rdap+json, application/json;q=0.9',
      },
      signal: AbortSignal.timeout(4500),
    });
    if (!res.ok) {
      const fallback = await fetchRipeStatWhoisFallback(ip, lang);
      if (fallback) return fallback;
      return {
        rdap: null,
        check: {
          source,
          status: res.status === 404 ? 'not_found' : 'error',
          summary:
            res.status === 404
              ? lang === 'tr'
                ? 'RDAP kaydı bulunamadı.'
                : 'No RDAP record found.'
              : `HTTP ${res.status}`,
          details: {},
        },
      };
    }

    const data = (await res.json()) as {
      handle?: string;
      name?: string;
      country?: string;
      type?: string;
      port43?: string;
      startAddress?: string;
      endAddress?: string;
      cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
      status?: string[];
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      links?: Array<{ href?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[]; entities?: unknown[] }>;
    };

    const cidrFromObj = data.cidr0_cidrs?.[0]
      ? `${data.cidr0_cidrs[0].v4prefix || data.cidr0_cidrs[0].v6prefix}/${data.cidr0_cidrs[0].length ?? ''}`
      : null;
    const rangeFallback =
      data.startAddress && data.endAddress ? `${data.startAddress} - ${data.endAddress}` : null;
    const cidr = cidrFromObj || rangeFallback;
    const rir = inferRirFromRdap(data);
    const registeredDate = data.events?.find((e) => e.eventAction === 'registration')?.eventDate || null;
    const lastChangedDate = data.events?.find((e) => e.eventAction === 'last changed')?.eventDate || null;
    const abuseContacts = extractRdapAbuseContacts(data.entities);
    const statusList = Array.isArray(data.status) ? data.status.slice(0, 6) : [];

    const details: Record<string, string | string[]> = {};
    if (rir) details.RIR = rir;
    if (data.name) details[lang === 'tr' ? 'agAdi' : 'netname'] = data.name;
    if (cidr) details.CIDR = cidr;
    if (data.handle) details.handle = data.handle;
    if (data.country) details[lang === 'tr' ? 'ulke' : 'country'] = data.country;
    if (abuseContacts.length > 0) details[lang === 'tr' ? 'ihlalIletisim' : 'abuseContact'] = abuseContacts;
    if (registeredDate) details[lang === 'tr' ? 'kayitTarihi' : 'registered'] = registeredDate.slice(0, 10);

    return {
      rdap: {
        handle: data.handle || null,
        name: data.name || null,
        cidr,
        rir,
        country: data.country || null,
        type: data.type || null,
        status: statusList,
        abuseContacts,
        registeredDate,
        lastChangedDate,
      },
      check: {
        source,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${rir || 'RIR'} resmi kaydı doğrulandı${data.name ? `: ${data.name}` : ''}.`
            : `Verified via ${rir || 'RIR'}${data.name ? `: ${data.name}` : ''}.`,
        details,
      },
    };
  } catch {
    const fallback = await fetchRipeStatWhoisFallback(ip, lang);
    if (fallback) return fallback;
    return {
      rdap: null,
      check: {
        source,
        status: 'error',
        summary: lang === 'tr' ? 'RDAP servisine ulaşılamadı.' : 'Could not reach RDAP service.',
        details: {},
      },
    };
  }
}

interface GeoLookupResult {
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  postal: string | null;
  timezone: string | null;
  coordinates: { lat: number; lon: number } | null;
  isp: string | null;
  organization: string | null;
  asn: string | null;
  asnName: string | null;
  reverseHost: string | null;
  flags: { hosting: boolean; proxy: boolean; mobile: boolean };
  checks: IpOsintSourceResult[];
}

async function checkIpGeoAndFlags(ip: string, lang: Lang): Promise<GeoLookupResult> {
  const whoisSource = lang === 'tr' ? 'ipwho.is Konum & Ağ' : 'ipwho.is Geo & Network';
  const ipApiSource = lang === 'tr' ? 'ip-api.com Altyapı & Proxy Analizi' : 'ip-api.com Infra & Proxy Check';

  const [whoRes, apiRes] = await Promise.all([
    fetchWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`, 4500).catch(() => null),
    fetchWithTimeout(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting`,
      4500,
    ).catch(() => null),
  ]);

  interface IpWhoResponse {
    success?: boolean;
    country?: string;
    country_code?: string;
    region?: string;
    city?: string;
    postal?: string;
    latitude?: number;
    longitude?: number;
    timezone?: { id?: string; utc?: string };
    connection?: { asn?: number; org?: string; isp?: string; domain?: string };
    message?: string;
  }

  interface IpApiResponse {
    status?: string;
    message?: string;
    country?: string;
    countryCode?: string;
    regionName?: string;
    city?: string;
    zip?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    isp?: string;
    org?: string;
    as?: string;
    asname?: string;
    reverse?: string;
    mobile?: boolean;
    proxy?: boolean;
    hosting?: boolean;
  }

  let whoData: IpWhoResponse | null = null;
  if (whoRes?.ok) {
    whoData = (await whoRes.json().catch(() => null)) as IpWhoResponse | null;
  }

  let apiData: IpApiResponse | null = null;
  if (apiRes?.ok) {
    apiData = (await apiRes.json().catch(() => null)) as IpApiResponse | null;
  }

  const checks: IpOsintSourceResult[] = [];

  if (whoData?.success) {
    const tzLabel = whoData.timezone?.id
      ? `${whoData.timezone.id}${whoData.timezone.utc ? ` (${whoData.timezone.utc})` : ''}`
      : null;
    const d: Record<string, string> = {};
    if (whoData.country) d[lang === 'tr' ? 'ulke' : 'country'] = `${whoData.country}${whoData.country_code ? ` (${whoData.country_code})` : ''}`;
    if (whoData.city || whoData.region) d[lang === 'tr' ? 'sehirBolge' : 'cityRegion'] = [whoData.city, whoData.region].filter(Boolean).join(', ');
    if (whoData.connection?.isp) d.ISP = whoData.connection.isp;
    if (whoData.connection?.asn) d.ASN = `AS${whoData.connection.asn}`;
    if (tzLabel) d[lang === 'tr' ? 'zamanDilimi' : 'timezone'] = tzLabel;
    checks.push({
      source: whoisSource,
      status: 'found',
      summary: `${[whoData.city, whoData.country].filter(Boolean).join(', ') || whoData.connection?.isp || 'OK'}`,
      details: d,
    });
  } else {
    checks.push({
      source: whoisSource,
      status: 'error',
      summary: whoData?.message || (lang === 'tr' ? 'Konum verisi alınamadı.' : 'Geo lookup unavailable.'),
      details: {},
    });
  }

  if (apiData?.status === 'success') {
    const signals: string[] = [];
    if (apiData.hosting) signals.push(lang === 'tr' ? 'Veri Merkezi / Hosting' : 'Datacenter / Hosting');
    if (apiData.proxy) signals.push('Proxy / VPN');
    if (apiData.mobile) signals.push(lang === 'tr' ? 'Mobil Ağ' : 'Mobile Carrier');
    if (signals.length === 0) signals.push(lang === 'tr' ? 'Standart Konut / Sabit Hat' : 'Standard / Residential');

    const d: Record<string, string | string[]> = {
      [lang === 'tr' ? 'siniflandirma' : 'classification']: signals,
    };
    if (apiData.as) d.AS = apiData.as;
    if (apiData.org) d[lang === 'tr' ? 'kurum' : 'org'] = apiData.org;
    if (apiData.reverse) d.rDNS = apiData.reverse;
    checks.push({
      source: ipApiSource,
      status: 'found',
      summary: signals.join(' · '),
      details: d,
    });
  } else {
    checks.push({
      source: ipApiSource,
      status: 'error',
      summary: apiData?.message || (lang === 'tr' ? 'Altyapı sinyali alınamadı.' : 'Infrastructure check unavailable.'),
      details: {},
    });
  }

  const okWho = whoData?.success === true;
  const okApi = apiData?.status === 'success';
  const asMatch = apiData?.as?.match(/AS\d+/i)?.[0] || null;
  const asnFromWho = whoData?.connection?.asn ? `AS${whoData.connection.asn}` : null;

  const lat = okWho && typeof whoData?.latitude === 'number' ? whoData.latitude : okApi && typeof apiData?.lat === 'number' ? apiData.lat : null;
  const lon = okWho && typeof whoData?.longitude === 'number' ? whoData.longitude : okApi && typeof apiData?.lon === 'number' ? apiData.lon : null;

  return {
    country: (okWho ? whoData?.country : null) || (okApi ? apiData?.country : null) || null,
    countryCode: (okWho ? whoData?.country_code : null) || (okApi ? apiData?.countryCode : null) || null,
    region: (okWho ? whoData?.region : null) || (okApi ? apiData?.regionName : null) || null,
    city: (okWho ? whoData?.city : null) || (okApi ? apiData?.city : null) || null,
    postal: (okWho ? whoData?.postal : null) || (okApi ? apiData?.zip : null) || null,
    timezone:
      (okWho && whoData?.timezone?.id
        ? `${whoData.timezone.id}${whoData.timezone.utc ? ` (${whoData.timezone.utc})` : ''}`
        : null) ||
      (okApi ? apiData?.timezone || null : null),
    coordinates: lat !== null && lon !== null ? { lat, lon } : null,
    isp: (okWho ? whoData?.connection?.isp : null) || (okApi ? apiData?.isp : null) || null,
    organization: (okWho ? whoData?.connection?.org : null) || (okApi ? apiData?.org : null) || null,
    asn: asnFromWho || asMatch,
    asnName: (okApi ? apiData?.asname : null) || (okWho ? whoData?.connection?.org : null) || null,
    reverseHost: okApi && apiData?.reverse ? apiData.reverse : null,
    flags: {
      hosting: Boolean(okApi && apiData?.hosting),
      proxy: Boolean(okApi && apiData?.proxy),
      mobile: Boolean(okApi && apiData?.mobile),
    },
    checks,
  };
}

async function checkRipeStatBgp(
  ip: string,
  lang: Lang,
): Promise<{ prefix: string | null; asns: string[]; check: IpOsintSourceResult }> {
  const source = lang === 'tr' ? 'RIPEstat BGP Yönlendirme' : 'RIPEstat BGP Routing';
  try {
    const res = await fetchWithTimeout(
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`,
      4500,
    );
    if (!res.ok) {
      return { prefix: null, asns: [], check: { source, status: 'error', summary: `HTTP ${res.status}`, details: {} } };
    }
    const json = (await res.json()) as { data?: { prefix?: string; asns?: string[] } };
    const prefix = json.data?.prefix || null;
    const asns = Array.isArray(json.data?.asns) ? json.data!.asns.map((a) => `AS${String(a).replace(/^AS/i, '')}`) : [];
    if (!prefix && asns.length === 0) {
      return {
        prefix: null,
        asns: [],
        check: {
          source,
          status: 'not_found',
          summary: lang === 'tr' ? 'BGP yönlendirme anonsu görülmedi.' : 'No BGP announcement observed.',
          details: {},
        },
      };
    }
    return {
      prefix,
      asns,
      check: {
        source,
        status: 'found',
        summary:
          lang === 'tr'
            ? `BGP Öneki ${prefix || '—'} (${asns.join(', ') || 'AS yok'}) üzerinden duyuruluyor.`
            : `Announced via BGP prefix ${prefix || '—'} (${asns.join(', ') || 'no AS'}).`,
        details: {
          ...(prefix ? { [lang === 'tr' ? 'anonsOneki' : 'announcedPrefix']: prefix } : {}),
          ...(asns.length > 0 ? { ASNs: asns } : {}),
        },
      },
    };
  } catch {
    return {
      prefix: null,
      asns: [],
      check: {
        source,
        status: 'error',
        summary: lang === 'tr' ? 'RIPEstat servisine ulaşılamadı.' : 'Could not reach RIPEstat.',
        details: {},
      },
    };
  }
}

async function checkShodanInternetDb(
  ip: string,
  lang: Lang,
): Promise<{
  ports: number[];
  vulns: string[];
  cpes: string[];
  tags: string[];
  hostnames: string[];
  check: IpOsintSourceResult;
}> {
  const source = 'Shodan InternetDB';
  try {
    const res = await fetchWithTimeout(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, 4200);
    if (res.status === 404) {
      return {
        ports: [],
        vulns: [],
        cpes: [],
        tags: [],
        hostnames: [],
        check: {
          source,
          status: 'not_found',
          summary:
            lang === 'tr'
              ? 'Shodan InternetDB indeksinde açık port veya servis kaydı yok.'
              : 'No open ports or service entries indexed on Shodan InternetDB.',
          details: {},
        },
      };
    }
    if (!res.ok) {
      return {
        ports: [],
        vulns: [],
        cpes: [],
        tags: [],
        hostnames: [],
        check: { source, status: 'error', summary: `HTTP ${res.status}`, details: {} },
      };
    }
    const data = (await res.json()) as {
      ports?: number[];
      vulns?: string[];
      cpes?: string[];
      tags?: string[];
      hostnames?: string[];
    };
    const ports = Array.isArray(data.ports) ? data.ports.filter((p) => typeof p === 'number').sort((a, b) => a - b) : [];
    const vulns = Array.isArray(data.vulns) ? data.vulns.filter(Boolean) : [];
    const cpes = Array.isArray(data.cpes) ? data.cpes.filter(Boolean) : [];
    const tags = Array.isArray(data.tags) ? data.tags.filter(Boolean) : [];
    const hostnames = Array.isArray(data.hostnames) ? data.hostnames.filter(Boolean) : [];

    const details: Record<string, string | string[]> = {};
    if (ports.length > 0) details[lang === 'tr' ? 'acikPortlar' : 'openPorts'] = ports.map(String);
    if (tags.length > 0) details[lang === 'tr' ? 'etiketler' : 'tags'] = tags;
    if (hostnames.length > 0) details[lang === 'tr' ? 'alanAdlari' : 'hostnames'] = hostnames.slice(0, 10);
    if (vulns.length > 0) details.CVEs = vulns.slice(0, 12);

    return {
      ports,
      vulns,
      cpes,
      tags,
      hostnames,
      check: {
        source,
        status: ports.length > 0 || vulns.length > 0 ? 'found' : 'info',
        summary:
          lang === 'tr'
            ? `${ports.length} açık port${vulns.length > 0 ? `, ${vulns.length} bilinen CVE` : ''} tespit edildi.`
            : `Detected ${ports.length} open port(s)${vulns.length > 0 ? `, ${vulns.length} known CVE(s)` : ''}.`,
        details,
      },
    };
  } catch {
    return {
      ports: [],
      vulns: [],
      cpes: [],
      tags: [],
      hostnames: [],
      check: {
        source,
        status: 'error',
        summary: lang === 'tr' ? 'Shodan InternetDB zaman aşımı.' : 'Shodan InternetDB timed out.',
        details: {},
      },
    };
  }
}

async function checkTorOnionoo(
  ip: string,
  lang: Lang,
): Promise<{ isTor: boolean; check: IpOsintSourceResult }> {
  const source = lang === 'tr' ? 'Tor Project Düğüm Kontrolü' : 'Tor Project Onionoo Check';
  try {
    const res = await fetchWithTimeout(
      `https://onionoo.torproject.org/details?search=${encodeURIComponent(ip)}&limit=3`,
      4200,
    );
    if (!res.ok) {
      return { isTor: false, check: { source, status: 'error', summary: `HTTP ${res.status}`, details: {} } };
    }
    const data = (await res.json()) as {
      relays?: Array<{
        nickname?: string;
        running?: boolean;
        flags?: string[];
        or_addresses?: string[];
        exit_addresses?: string[];
        country_name?: string;
      }>;
    };
    const exactRelays = (data.relays || []).filter((relay) => {
      const addrs = [...(relay.or_addresses || []), ...(relay.exit_addresses || [])];
      return addrs.some((addr) => {
        const cleaned = addr.startsWith('[')
          ? addr.slice(1, addr.indexOf(']'))
          : addr.split(':')[0];
        return cleaned.toLowerCase() === ip.toLowerCase();
      });
    });

    if (exactRelays.length === 0) {
      return {
        isTor: false,
        check: {
          source,
          status: 'not_found',
          summary:
            lang === 'tr'
              ? 'Tor Project resmi listesinde aktif veya kayıtlı çıkış düğümü değil.'
              : 'Not listed as an active or recent Tor relay/exit node.',
          details: {},
        },
      };
    }

    const active = exactRelays.some((r) => r.running);
    return {
      isTor: true,
      check: {
        source,
        status: 'found',
        summary:
          lang === 'tr'
            ? `Tor ağı düğümü olarak doğrulandı (${active ? 'Aktif' : 'Geçmiş Kayıt'}).`
            : `Confirmed Tor network node (${active ? 'Active' : 'Historical'}).`,
        details: {
          [lang === 'tr' ? 'dugumler' : 'relays']: exactRelays.map(
            (r) => `${r.nickname || 'Unnamed'} (${r.running ? 'Running' : 'Offline'}) [${(r.flags || []).join(', ')}]`,
          ),
        },
      },
    };
  } catch {
    return {
      isTor: false,
      check: {
        source,
        status: 'error',
        summary: lang === 'tr' ? 'Tor Onionoo servisine ulaşılamadı.' : 'Could not reach Tor Onionoo.',
        details: {},
      },
    };
  }
}

async function checkReverseDns(
  ip: string,
  version: 4 | 6,
  lang: Lang,
): Promise<{ ptrHostnames: string[]; fcrdnsVerified: boolean; check: IpOsintSourceResult }> {
  const source = lang === 'tr' ? 'Ters DNS (PTR & FCrDNS)' : 'Reverse DNS (PTR & FCrDNS)';
  try {
    const ptrs = await dns.reverse(ip).catch(() => []);
    if (ptrs.length === 0) {
      return {
        ptrHostnames: [],
        fcrdnsVerified: false,
        check: {
          source,
          status: 'not_found',
          summary: lang === 'tr' ? 'PTR (Reverse DNS) kaydı tanımlı değil.' : 'No PTR (Reverse DNS) record found.',
          details: {},
        },
      };
    }

    let fcrdnsVerified = false;
    const firstPtr = ptrs[0];
    try {
      const resolved = version === 4 ? await dns.resolve4(firstPtr) : await dns.resolve6(firstPtr);
      fcrdnsVerified = resolved.some((addr) => addr.toLowerCase() === ip.toLowerCase());
    } catch {
      fcrdnsVerified = false;
    }

    return {
      ptrHostnames: ptrs,
      fcrdnsVerified,
      check: {
        source,
        status: 'found',
        summary:
          lang === 'tr'
            ? `${firstPtr} (${fcrdnsVerified ? 'Çift yönlü DNS doğrulandı' : 'Yalnızca PTR'})`
            : `${firstPtr} (${fcrdnsVerified ? 'FCrDNS verified' : 'PTR only'})`,
        details: {
          PTR: ptrs,
          FCrDNS: fcrdnsVerified ? (lang === 'tr' ? 'Doğrulandı' : 'Verified') : lang === 'tr' ? 'Doğrulanamadı' : 'Unverified',
        },
      },
    };
  } catch {
    return {
      ptrHostnames: [],
      fcrdnsVerified: false,
      check: {
        source,
        status: 'not_found',
        summary: lang === 'tr' ? 'PTR kaydı çözümlenemedi.' : 'PTR lookup failed.',
        details: {},
      },
    };
  }
}

interface CachedIpReport {
  expiresAt: number;
  report: Omit<IpOsintReport, 'durationMs' | 'checkedAt'>;
}

const IP_CACHE_TTL_MS = 60_000;
const MAX_IP_CACHE = 400;
const ipOsintCache = new Map<string, CachedIpReport>();
const inflightIpLookups = new Map<string, Promise<Omit<IpOsintReport, 'durationMs' | 'checkedAt'>>>();

export async function runIpOsint(
  rawIp: string,
  lang: Lang = 'tr',
  opts: { skipNetwork?: boolean } = {},
): Promise<IpOsintReport> {
  const start = Date.now();
  const parsed = isValidIpAddress(rawIp);

  if (!parsed.valid || parsed.version === 0) {
    return {
      ip: String(rawIp || '').trim(),
      version: 4,
      isValid: false,
      isPublic: false,
      scopeNote: lang === 'tr' ? 'Geçersiz IP adresi formatı' : 'Invalid IP address format',
      country: null,
      countryCode: null,
      region: null,
      city: null,
      postal: null,
      timezone: null,
      coordinates: null,
      isp: null,
      organization: null,
      asn: null,
      asnName: null,
      prefix: null,
      rdap: null,
      ptrHostnames: [],
      fcrdnsVerified: false,
      flags: { hosting: false, proxy: false, mobile: false, torExit: false },
      openPorts: [],
      vulns: [],
      cpes: [],
      tags: [],
      hostnames: [],
      externalChecks: [],
      pivotLinks: [],
      checkedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };
  }

  const version = parsed.version;
  const scope = classifyIpScope(parsed.ip, version, lang);
  const encodedIp = encodeURIComponent(parsed.ip);

  if (!scope.isPublic || opts.skipNetwork) {
    return {
      ip: parsed.ip,
      version,
      isValid: true,
      isPublic: scope.isPublic,
      scopeNote: scope.note,
      country: null,
      countryCode: null,
      region: null,
      city: null,
      postal: null,
      timezone: null,
      coordinates: null,
      isp: null,
      organization: null,
      asn: null,
      asnName: null,
      prefix: null,
      rdap: null,
      ptrHostnames: [],
      fcrdnsVerified: false,
      flags: { hosting: false, proxy: false, mobile: false, torExit: false },
      openPorts: [],
      vulns: [],
      cpes: [],
      tags: [],
      hostnames: [],
      externalChecks: [
        {
          source: lang === 'tr' ? 'RFC IP Kapsam Sınıflandırması' : 'RFC IP Scope Classification',
          status: 'info',
          summary: scope.isPublic
            ? lang === 'tr'
              ? 'Genel yönlendirilebilir IP (çevrimdışı test modu).'
              : 'Public routable IP (offline test mode).'
            : lang === 'tr'
              ? `${scope.note} — özel/ayrılmış adresler için genel internet kaydı bulunmaz.`
              : `${scope.note} — no public registry records exist for private/reserved ranges.`,
          details: {
            IP: parsed.ip,
            [lang === 'tr' ? 'surum' : 'version']: `IPv${version}`,
            [lang === 'tr' ? 'kapsam' : 'scope']: scope.note,
          },
        },
      ],
      pivotLinks: scope.isPublic
        ? [
            { label: 'RIPEstat', url: `https://stat.ripe.net/app/launchpad/${encodedIp}` },
            { label: 'Shodan', url: `https://www.shodan.io/host/${encodedIp}` },
            { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${encodedIp}` },
            { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${encodedIp}` },
            { label: 'Hurricane Electric BGP', url: `https://bgp.he.net/ip/${encodedIp}` },
            { label: 'RDAP', url: `https://rdap.org/ip/${encodedIp}` },
          ]
        : [],
      checkedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };
  }

  const cacheKey = `${parsed.ip}:${lang}`;
  const cached = ipOsintCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return {
      ...cached.report,
      checkedAt: new Date().toISOString(),
      durationMs: Math.max(1, Date.now() - start),
    };
  }

  let task = inflightIpLookups.get(cacheKey);
  if (!task) {
    task = (async () => {
      const [rdapRes, geoRes, ripeRes, shodanRes, torRes, ptrRes] = await Promise.all([
        checkIpRdap(parsed.ip, lang),
        checkIpGeoAndFlags(parsed.ip, lang),
        checkRipeStatBgp(parsed.ip, lang),
        checkShodanInternetDb(parsed.ip, lang),
        checkTorOnionoo(parsed.ip, lang),
        checkReverseDns(parsed.ip, version, lang),
      ]);

      const ptrCombined = Array.from(
        new Set([...ptrRes.ptrHostnames, ...(geoRes.reverseHost ? [geoRes.reverseHost] : [])].filter(Boolean)),
      );
      const allHostnames = Array.from(new Set([...ptrCombined, ...shodanRes.hostnames]));
      const asnFinal = geoRes.asn || ripeRes.asns[0] || null;

      return {
        ip: parsed.ip,
        version,
        isValid: true,
        isPublic: true,
        scopeNote: scope.note,
        country: geoRes.country || rdapRes.rdap?.country || null,
        countryCode: geoRes.countryCode || rdapRes.rdap?.country || null,
        region: geoRes.region,
        city: geoRes.city,
        postal: geoRes.postal,
        timezone: geoRes.timezone,
        coordinates: geoRes.coordinates,
        isp: geoRes.isp,
        organization: geoRes.organization || rdapRes.rdap?.name || null,
        asn: asnFinal,
        asnName: geoRes.asnName || rdapRes.rdap?.name || null,
        prefix: ripeRes.prefix || rdapRes.rdap?.cidr || null,
        rdap: rdapRes.rdap,
        ptrHostnames: ptrCombined,
        fcrdnsVerified: ptrRes.fcrdnsVerified,
        flags: {
          hosting: geoRes.flags.hosting || shodanRes.tags.includes('cloud') || shodanRes.tags.includes('cdn'),
          proxy: geoRes.flags.proxy || shodanRes.tags.includes('vpn') || shodanRes.tags.includes('proxy') || torRes.isTor,
          mobile: geoRes.flags.mobile,
          torExit: torRes.isTor || shodanRes.tags.includes('tor'),
        },
        openPorts: shodanRes.ports,
        vulns: shodanRes.vulns,
        cpes: shodanRes.cpes,
        tags: shodanRes.tags,
        hostnames: allHostnames,
        externalChecks: [
          rdapRes.check,
          ...geoRes.checks,
          ripeRes.check,
          shodanRes.check,
          torRes.check,
          ptrRes.check,
        ],
        pivotLinks: [
          { label: 'RIPEstat', url: `https://stat.ripe.net/app/launchpad/${encodedIp}` },
          { label: 'Shodan', url: `https://www.shodan.io/host/${encodedIp}` },
          { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${encodedIp}` },
          { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${encodedIp}` },
          { label: 'Hurricane Electric BGP', url: `https://bgp.he.net/ip/${encodedIp}` },
          { label: 'RDAP', url: `https://rdap.org/ip/${encodedIp}` },
        ],
      };
    })().finally(() => {
      inflightIpLookups.delete(cacheKey);
    });

    inflightIpLookups.set(cacheKey, task);
  }

  const baseReport = await task;
  if (ipOsintCache.size >= MAX_IP_CACHE) {
    const oldestKey = ipOsintCache.keys().next().value;
    if (oldestKey) ipOsintCache.delete(oldestKey);
  }
  ipOsintCache.set(cacheKey, {
    expiresAt: Date.now() + IP_CACHE_TTL_MS,
    report: baseReport,
  });

  return {
    ...baseReport,
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - start,
  };
}
