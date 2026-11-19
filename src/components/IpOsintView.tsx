import { useState, type FormEvent } from 'react';
import { Globe, Search, AlertCircle, CheckCircle2, Info, ExternalLink, Shield, Server } from 'lucide-react';
import type { IpOsintReport, PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { ApiError, apiIpOsint } from '../utils/api';

interface IpOsintViewProps {
  currentUser: PublicUser;
  onUserUpdate: (u: PublicUser) => void;
  onUnauthorized?: () => void;
}

const SAMPLE_IPS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

export function IpOsintView({ onUserUpdate, onUnauthorized }: IpOsintViewProps) {
  const { lang, t } = useI18n();
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<IpOsintReport | null>(null);

  const runLookup = async (targetIp: string) => {
    const trimmed = targetIp.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiIpOsint(trimmed, lang);
      setReport(res.report);
      onUserUpdate(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized?.();
        return;
      }
      setError(
        err instanceof Error
          ? err.message
          : t('IP sorgulama işlemi başarısız oldu.', 'IP lookup failed.'),
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await runLookup(ipInput);
  };

  const matchedChecksCount = report
    ? report.externalChecks.filter((c) => c.status === 'found').length
    : 0;

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <div className="max-w-3xl">
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('IP Sorgu ve Yasal Açık Kaynak İstihbaratı', 'IP Lookup & Legal Open-Source Intelligence')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              'Yüklü bir veri setine ihtiyaç duymadan yalnızca halka açık resmi ve yasal kaynaklar (RDAP, RIPEstat BGP/ASN, ipwho.is, ip-api, Shodan InternetDB, Tor Project Onionoo ve Reverse DNS) üzerinden IPv4 / IPv6 analizini anlık olarak gerçekleştirir.',
              'Analyzes IPv4 / IPv6 addresses in real time with zero uploaded datasets required, using public legal registries and feeds (RDAP, RIPEstat BGP/ASN, ipwho.is, ip-api, Shodan InternetDB, Tor Project Onionoo, and Reverse DNS).',
            )}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <label htmlFor="ip-osint-input" className="sr-only">
              {t('Sorgulanacak IPv4 veya IPv6 Adresi', 'IPv4 or IPv6 Address to Lookup')}
            </label>
            <Globe className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              id="ip-osint-input"
              type="text"
              required
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder={t('Örn: 1.1.1.1, 8.8.8.8 veya 2606:4700:4700::1111', 'e.g., 1.1.1.1, 8.8.8.8 or 2606:4700:4700::1111')}
              className="w-full rounded-lg border border-slate-300 bg-slate-50 py-2.5 pl-10 pr-4 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Search className="h-4 w-4" />
            <span>{loading ? t('Sorgulanıyor...', 'Querying...') : t('IP Sorgula', 'Lookup IP')}</span>
          </button>
        </form>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <span>{t('Hızlı örnek:', 'Quick test:')}</span>
          {SAMPLE_IPS.map((sample) => (
            <button
              key={sample}
              type="button"
              onClick={() => {
                setIpInput(sample);
                void runLookup(sample);
              }}
              className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 font-mono text-xs text-slate-700 transition-colors hover:border-blue-500 hover:text-blue-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:text-blue-400"
            >
              {sample}
            </button>
          ))}
        </div>

        {error && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {loading && !report && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-28 animate-pulse rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]"
            />
          ))}
        </div>
      )}

      {!report && !loading && (
        <section className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-[#111827]">
          <div className="flex items-start gap-3">
            <Shield className="mt-0.5 h-5 w-5 text-blue-600 dark:text-blue-400 shrink-0" />
            <div className="space-y-1.5 text-sm">
              <h3 className="font-display font-semibold text-slate-900 dark:text-slate-100">
                {t('Verisiz Anlık IP Analizi Hazır', 'Zero-Dataset Instant IP Analysis Ready')}
              </h3>
              <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                {t(
                  'Herhangi bir yerel arşiv dosyası yüklü olmasa dahi hedef IP adresinin coğrafi konumunu, ISP/ASN sahibini, BGP yönlendirme önekini, RIR/RDAP tahsis ve abuse iletişim bilgilerini, Reverse DNS (FCrDNS) çözümlemesini, Shodan açık port/CVE özetini ve Tor çıkış düğümü durumunu tek sorguda toplar.',
                  'Even with zero datasets uploaded, this module resolves geolocation, ISP/ASN owner, BGP announced prefix, official RIR/RDAP allocation & abuse contacts, Reverse DNS (FCrDNS), Shodan open ports/CVEs, and Tor relay status in a single lookup.',
                )}
              </p>
            </div>
          </div>
        </section>
      )}

      {report && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {t('Hedef:', 'Target:')} <span className="font-mono tabular-nums">{report.ip}</span>
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono">IPv{report.version}</span>
            <span aria-hidden="true">·</span>
            <span>{report.scopeNote}</span>
            {report.asn && (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">{report.asn}</span>
              </>
            )}
            <span aria-hidden="true">·</span>
            <span className="font-semibold text-blue-600 dark:text-blue-400">
              {matchedChecksCount} / {report.externalChecks.length} {t('kaynakta veri doğrulandı', 'sources returned data')}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{report.durationMs} ms</span>
          </div>

          <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('Ağ, Konum ve Altyapı Özeti', 'Network, Location & Infrastructure Summary')}
              </h3>
              <div className="text-xs font-medium text-slate-600 dark:text-slate-300">
                {report.isPublic
                  ? report.flags.torExit
                    ? t('Tor Çıkış / Röle Düğümü', 'Tor Exit / Relay Node')
                    : report.flags.proxy
                      ? t('VPN / Proxy Sinyali', 'VPN / Proxy Signal')
                      : report.flags.hosting
                        ? t('Veri Merkezi / Hosting', 'Datacenter / Hosting')
                        : report.flags.mobile
                          ? t('Mobil Operatör Ağı', 'Mobile Carrier')
                          : t('Standart Genel Ağ', 'Standard Public Network')
                  : t('Yerel / Özel Ağ Adresi', 'Private / Reserved Range')}
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {t('Konum ve Zaman Dilimi', 'Location & Timezone')}
                </div>
                <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {[report.city, report.region, report.country].filter(Boolean).join(', ') || '—'}
                </div>
                <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                  {report.timezone || '—'}
                  {report.coordinates
                    ? ` · ${report.coordinates.lat.toFixed(4)}, ${report.coordinates.lon.toFixed(4)}`
                    : ''}
                </div>
              </div>

              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {t('ISP ve Kurum', 'ISP & Organization')}
                </div>
                <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {report.isp || report.organization || '—'}
                </div>
                {report.organization && report.organization !== report.isp && (
                  <div className="mt-1 text-xs text-slate-600 dark:text-slate-400 truncate" title={report.organization}>
                    {report.organization}
                  </div>
                )}
              </div>

              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {t('ASN ve BGP Yönlendirme Öneki', 'ASN & BGP Announced Prefix')}
                </div>
                <div className="mt-1 font-mono text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
                  {report.asn || '—'}
                </div>
                <div className="mt-1 font-mono text-xs tabular-nums text-slate-600 dark:text-slate-400">
                  {report.prefix || report.rdap?.cidr || '—'}
                </div>
              </div>

              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  {t('Reverse DNS (PTR / FCrDNS)', 'Reverse DNS (PTR / FCrDNS)')}
                </div>
                <div className="mt-1 font-mono text-xs break-all text-slate-900 dark:text-slate-100">
                  {report.ptrHostnames.length > 0 ? report.ptrHostnames[0] : t('PTR kaydı yok', 'No PTR record')}
                </div>
                {report.ptrHostnames.length > 0 && (
                  <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    {report.fcrdnsVerified
                      ? t('Çift yönlü DNS doğrulandı (FCrDNS)', 'Forward-confirmed rDNS verified')
                      : t('Yalnızca ters DNS kaydı', 'PTR only (unconfirmed forward)')}
                  </div>
                )}
              </div>
            </div>
          </section>

          {report.rdap && (
            <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('RDAP Resmi Blok Tahsisi', 'Official RDAP Allocation')}
              </h3>
              <div className="mt-3 grid grid-cols-1 gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <div className="text-slate-500 dark:text-slate-400">{t('Bölgesel Kayıt (RIR)', 'Registry (RIR)')}</div>
                  <div className="mt-1 font-semibold text-slate-900 dark:text-slate-100">
                    {report.rdap.rir || '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">{t('Ağ Adı / Handle', 'Netname / Handle')}</div>
                  <div className="mt-1 font-mono text-slate-900 dark:text-slate-100 break-all">
                    {[report.rdap.name, report.rdap.handle].filter(Boolean).join(' · ') || '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">{t('Kayıt / Güncelleme', 'Registered / Changed')}</div>
                  <div className="mt-1 font-mono tabular-nums text-slate-800 dark:text-slate-200">
                    {report.rdap.registeredDate ? report.rdap.registeredDate.slice(0, 10) : '—'}
                    {report.rdap.lastChangedDate ? ` / ${report.rdap.lastChangedDate.slice(0, 10)}` : ''}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">{t('Abuse / NOC İletişim', 'Abuse / NOC Contact')}</div>
                  <div className="mt-1 font-mono text-blue-600 dark:text-blue-400 break-all">
                    {report.rdap.abuseContacts.length > 0 ? report.rdap.abuseContacts.join(', ') : '—'}
                  </div>
                </div>
              </div>
            </section>
          )}

          {(report.openPorts.length > 0 || report.vulns.length > 0 || report.hostnames.length > 0 || report.tags.length > 0) && (
            <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {t('Açık Portlar, Ana Bilgisayar Adları ve Bilinen CVE Özeti', 'Exposed Ports, Hostnames & Known CVEs')}
                </h3>
              </div>
              <div className="mt-4 grid grid-cols-1 gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <div className="text-slate-500 dark:text-slate-400">
                    {t('Açık Portlar', 'Open Ports')} ({report.openPorts.length})
                  </div>
                  <div className="mt-1 font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {report.openPorts.length > 0 ? report.openPorts.join(', ') : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">
                    {t('Bilinen CVE Zafiyetleri', 'Known CVEs')} ({report.vulns.length})
                  </div>
                  <div className="mt-1 font-mono tabular-nums text-amber-700 dark:text-amber-300">
                    {report.vulns.length > 0 ? report.vulns.slice(0, 12).join(', ') : t('Tespit edilmedi', 'None reported')}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">
                    {t('Servis Etiketleri', 'Service Tags')} ({report.tags.length})
                  </div>
                  <div className="mt-1 font-mono text-slate-800 dark:text-slate-200">
                    {report.tags.length > 0 ? report.tags.join(', ') : '—'}
                  </div>
                </div>
                <div>
                  <div className="text-slate-500 dark:text-slate-400">
                    {t('İlişkili Alan Adları', 'Associated Hostnames')} ({report.hostnames.length})
                  </div>
                  <div className="mt-1 font-mono break-all text-slate-800 dark:text-slate-200">
                    {report.hostnames.length > 0 ? report.hostnames.slice(0, 6).join(', ') : '—'}
                  </div>
                </div>
              </div>
            </section>
          )}

          <section className="space-y-3">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('Eşzamanlı Yasal Kaynak Doğrulamaları', 'Simultaneous Legal Source Checks')} ({report.externalChecks.length})
            </h3>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {report.externalChecks.map((chk) => (
                <div
                  key={chk.source}
                  className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-[#111827]"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                      {chk.source}
                    </span>
                    {chk.status === 'found' ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                    ) : chk.status === 'error' ? (
                      <AlertCircle className="h-4 w-4 text-slate-400 shrink-0" />
                    ) : (
                      <Info className="h-4 w-4 text-blue-500 shrink-0" />
                    )}
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                    {chk.summary}
                  </p>
                  {Object.keys(chk.details).length > 0 && (
                    <div className="mt-3 space-y-2 border-t border-slate-200 pt-2.5 text-[11px] dark:border-slate-800">
                      {Object.entries(chk.details).map(([k, v]) => (
                        <div key={k} className="break-all font-mono text-slate-600 dark:text-slate-400">
                          <span className="font-semibold text-slate-700 dark:text-slate-300">{k}: </span>
                          {Array.isArray(v) ? v.join(', ') : v}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {report.pivotLinks.length > 0 && (
            <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('Resmi ve Yasal Harici Doğrulama Portalları', 'Official Legal External Lookup Portals')}
              </h3>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                {t(
                  'Ek itibar, BGP geçmişi veya port doğrulaması için resmi yasal analiz portallarında açın.',
                  'Open directly in official legal reputation, BGP history, or host inspection portals.',
                )}
              </p>
              <div className="mt-3 flex flex-wrap gap-2.5">
                {report.pivotLinks.map((link) => (
                  <a
                    key={link.label}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-800 transition-colors hover:border-blue-500 hover:text-blue-600 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:text-blue-400"
                  >
                    <span>{link.label}</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
