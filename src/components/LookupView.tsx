import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  Search,
  AlertCircle,
  UserRound,
  Filter,
  Database,
  RotateCcw,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Mail,
  Phone,
  Globe,
  AtSign,
  Tag,
} from 'lucide-react';
import type { DatabaseSourceType, IntelRecord, PublicUser, SearchResult } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { SnowflakePanel } from './SnowflakePanel';
import { RecordTable } from './RecordTable';
import { formatTurkishDate } from '../utils/snowflake';
import { classifyRecordDatabaseType, isTimestampLikeValue } from '../utils/search';

interface LookupViewProps {
  currentUser: PublicUser;
  query: string;
  onQueryChange: (q: string) => void;
  result: SearchResult | null;
  searching: boolean;
  searchError: string | null;
  onRunSearch: (overrideQuery?: string) => void;
  onPivotEmail: (email: string) => void;
}

type DbTypeFilter = 'all' | DatabaseSourceType;
type MatchScopeFilter = 'all' | 'primary' | 'related';
type FieldPresenceFilter = 'all' | 'has_email' | 'has_contact' | 'has_extra';

interface AttributePanelProps {
  title: string;
  items: string[];
  emptyText: string;
  icon: 'user' | 'email' | 'phone' | 'ip' | 'source';
  onItemAction?: (val: string) => void;
  itemActionTitle?: string;
}

function AttributePanel({
  title,
  items,
  emptyText,
  icon,
  onItemAction,
  itemActionTitle,
}: AttributePanelProps) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const [inlineQuery, setInlineQuery] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    setExpanded(false);
    setInlineQuery('');
  }, [items]);

  const filteredItems = useMemo(() => {
    const q = inlineQuery.trim().toLowerCase();
    if (!q) return items;
    return items.filter((item) => item.toLowerCase().includes(q));
  }, [items, inlineQuery]);

  const PREVIEW_LIMIT = 5;
  const visibleItems = expanded ? filteredItems : filteredItems.slice(0, PREVIEW_LIMIT);
  const hiddenCount = Math.max(0, filteredItems.length - PREVIEW_LIMIT);

  const copyValue = async (key: string, val: string) => {
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      setCopiedId(key);
      setTimeout(() => setCopiedId(null), 1300);
    } catch {
      // Ignore clipboard errors
    }
  };

  const IconComp =
    icon === 'email'
      ? Mail
      : icon === 'phone'
        ? Phone
        : icon === 'ip'
          ? Globe
          : icon === 'source'
            ? Tag
            : AtSign;

  return (
    <div className="flex flex-col rounded-xl border border-slate-200/90 bg-slate-50/50 dark:border-slate-800 dark:bg-slate-900/40">
      <div className="flex items-center justify-between gap-2 border-b border-slate-200/80 px-3.5 py-2.5 dark:border-slate-800">
        <div className="flex min-w-0 items-center gap-2">
          <IconComp className="h-3.5 w-3.5 shrink-0 text-slate-500 dark:text-slate-400" />
          <span className="truncate text-xs font-semibold text-slate-800 dark:text-slate-200">{title}</span>
          <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
            ({items.length})
          </span>
        </div>
        {items.length > 0 && (
          <button
            type="button"
            onClick={() => void copyValue('all', items.join('\n'))}
            title={t('Tüm listeyi alt alta kopyala', 'Copy list line-by-line')}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold text-slate-600 transition-colors hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:text-white"
          >
            {copiedId === 'all' ? (
              <>
                <Check className="h-3 w-3 text-emerald-500" />
                <span className="text-emerald-600 dark:text-emerald-400">{t('Kopyalandı', 'Copied')}</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                <span>{t('Kopyala', 'Copy')}</span>
              </>
            )}
          </button>
        )}
      </div>

      {expanded && items.length > 8 && (
        <div className="border-b border-slate-200/80 px-3 py-2 dark:border-slate-800">
          <input
            type="text"
            value={inlineQuery}
            onChange={(e) => setInlineQuery(e.target.value)}
            placeholder={t('Liste içinde ara...', 'Filter list...')}
            className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1 font-mono text-[11px] text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
          />
        </div>
      )}

      {items.length === 0 ? (
        <div className="px-3.5 py-3 text-xs text-slate-400 dark:text-slate-500">{emptyText}</div>
      ) : visibleItems.length === 0 ? (
        <div className="px-3.5 py-3 text-xs text-slate-400 dark:text-slate-500">
          {t('Filtreye uyan kayıt yok', 'No matching items')}
        </div>
      ) : (
        <ul className="divide-y divide-slate-200/60 dark:divide-slate-800/70">
          {visibleItems.map((val, idx) => (
            <li
              key={`${val}_${idx}`}
              className="group flex items-center justify-between gap-2 px-3.5 py-2 text-xs transition-colors hover:bg-white/70 dark:hover:bg-slate-800/40"
            >
              {onItemAction ? (
                <button
                  type="button"
                  onClick={() => onItemAction(val)}
                  title={itemActionTitle}
                  className="min-w-0 truncate text-left font-mono font-medium text-blue-600 hover:underline dark:text-blue-400"
                >
                  {val}
                </button>
              ) : (
                <span className="min-w-0 truncate font-mono text-slate-900 dark:text-slate-100" title={val}>
                  {val}
                </span>
              )}
              <button
                type="button"
                onClick={() => void copyValue(`item_${idx}`, val)}
                aria-label={`Copy ${val}`}
                className="shrink-0 rounded p-1 text-slate-400 transition-colors hover:bg-slate-200/70 hover:text-slate-800 dark:hover:bg-slate-700 dark:hover:text-slate-100"
              >
                {copiedId === `item_${idx}` ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
              </button>
            </li>
          ))}
        </ul>
      )}

      {(hiddenCount > 0 || expanded) && (
        <div className="border-t border-slate-200/70 px-3.5 py-1.5 dark:border-slate-800">
          <button
            type="button"
            onClick={() => setExpanded((prev) => !prev)}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:underline dark:text-blue-400"
          >
            {expanded ? (
              <>
                <ChevronUp className="h-3.5 w-3.5" />
                <span>{t('Daralt', 'Collapse')}</span>
              </>
            ) : (
              <>
                <ChevronDown className="h-3.5 w-3.5" />
                <span>
                  {t(`Tümünü Göster (+${hiddenCount})`, `Show All (+${hiddenCount})`)}
                </span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}

export function LookupView({
  currentUser: _currentUser,
  query,
  onQueryChange,
  result,
  searching,
  searchError,
  onRunSearch,
  onPivotEmail,
}: LookupViewProps) {
  const { lang, t } = useI18n();
  const [resultFilterText, setResultFilterText] = useState('');
  const [resultDbTypeFilter, setResultDbTypeFilter] = useState<DbTypeFilter>('all');
  const [resultScopeFilter, setResultScopeFilter] = useState<MatchScopeFilter>('all');
  const [resultFilterType, setResultFilterType] = useState<FieldPresenceFilter>('all');
  const [resultSourceFilter, setResultSourceFilter] = useState('all');
  const [resultExtraKeyFilter, setResultExtraKeyFilter] = useState('all');
  const [headerCopied, setHeaderCopied] = useState<string | null>(null);
  const [expandedExtraKeys, setExpandedExtraKeys] = useState<Set<string>>(() => new Set());

  const resetAllFilters = () => {
    setResultFilterText('');
    setResultDbTypeFilter('all');
    setResultScopeFilter('all');
    setResultFilterType('all');
    setResultSourceFilter('all');
    setResultExtraKeyFilter('all');
  };

  useEffect(() => {
    resetAllFilters();
    setExpandedExtraKeys(new Set());
  }, [result]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    resetAllFilters();
    onRunSearch();
  };

  const copyHeaderValue = async (key: string, val: string) => {
    if (!val) return;
    try {
      await navigator.clipboard.writeText(val);
      setHeaderCopied(key);
      setTimeout(() => setHeaderCopied(null), 1300);
    } catch {
      // Ignore clipboard errors
    }
  };

  const toggleExtraFieldExpand = (key: string) => {
    setExpandedExtraKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const allMatchedRecords = useMemo(
    () => (result ? [...result.primaryMatches, ...result.relatedMatches] : []),
    [result],
  );

  const dbTypeCounts = useMemo(() => {
    const counts: Record<DatabaseSourceType, number> = {
      leak: 0,
      sizinti: 0,
      public_info: 0,
    };
    for (const rec of allMatchedRecords) {
      counts[classifyRecordDatabaseType(rec)] += 1;
    }
    return counts;
  }, [allMatchedRecords]);

  const uniqueUsernames = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.username.trim()).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniqueEmails = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.email.trim()).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniqueSources = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.source.trim()).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniquePhones = useMemo(
    () =>
      Array.from(
        new Set(
          allMatchedRecords
            .map((r) => r.phone.trim())
            .filter((p) => Boolean(p) && !isTimestampLikeValue(p)),
        ),
      ),
    [allMatchedRecords],
  );
  const uniqueIps = useMemo(
    () =>
      Array.from(
        new Set(
          allMatchedRecords
            .map((r) => r.ip.trim())
            .filter(Boolean),
        ),
      ),
    [allMatchedRecords],
  );

  const extraFieldsSummary = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const rec of allMatchedRecords) {
      for (const [k, rawVal] of Object.entries(rec.extra || {})) {
        const key = k.trim();
        const val = String(rawVal || '').trim();
        if (!key || !val) continue;
        let bucket = map.get(key);
        if (!bucket) {
          bucket = new Set<string>();
          map.set(key, bucket);
        }
        bucket.add(val);
      }
    }
    return Array.from(map.entries()).map(([key, values]) => ({
      key,
      values: Array.from(values),
    }));
  }, [allMatchedRecords]);

  const uniqueNotes = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.notes.trim()).filter(Boolean))),
    [allMatchedRecords],
  );

  const filterRecordList = useMemo(() => {
    const q = resultFilterText.trim().toLowerCase();
    return (list: IntelRecord[]) =>
      list.filter((r) => {
        const dbType = classifyRecordDatabaseType(r);
        if (resultDbTypeFilter !== 'all' && dbType !== resultDbTypeFilter) return false;
        if (resultFilterType === 'has_email' && !r.email.trim()) return false;
        if (
          resultFilterType === 'has_contact' &&
          !r.ip.trim() &&
          !(r.phone.trim() && !isTimestampLikeValue(r.phone))
        ) {
          return false;
        }
        if (
          resultFilterType === 'has_extra' &&
          !r.notes.trim() &&
          Object.values(r.extra || {}).every((v) => !String(v || '').trim())
        ) {
          return false;
        }
        if (resultSourceFilter !== 'all' && r.source !== resultSourceFilter) return false;
        if (resultExtraKeyFilter !== 'all') {
          const hasKey = Object.entries(r.extra || {}).some(
            ([k, v]) => k.trim() === resultExtraKeyFilter && String(v || '').trim() !== '',
          );
          if (!hasKey) return false;
        }
        if (!q) return true;
        const dbLabel =
          dbType === 'leak' ? 'leak' : dbType === 'sizinti' ? 'sızıntı sizinti breach' : 'public info osint açık';
        return (
          dbLabel.includes(q) ||
          r.discordId.toLowerCase().includes(q) ||
          r.email.toLowerCase().includes(q) ||
          r.username.toLowerCase().includes(q) ||
          r.source.toLowerCase().includes(q) ||
          r.ip.toLowerCase().includes(q) ||
          r.phone.toLowerCase().includes(q) ||
          r.notes.toLowerCase().includes(q) ||
          Object.entries(r.extra || {}).some(
            ([k, v]) => k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q),
          )
        );
      });
  }, [
    resultFilterText,
    resultDbTypeFilter,
    resultFilterType,
    resultSourceFilter,
    resultExtraKeyFilter,
  ]);

  const filteredPrimary = useMemo(() => {
    if (!result || resultScopeFilter === 'related') return [];
    return filterRecordList(result.primaryMatches);
  }, [result, resultScopeFilter, filterRecordList]);

  const filteredRelated = useMemo(() => {
    if (!result || resultScopeFilter === 'primary') return [];
    return filterRecordList(result.relatedMatches);
  }, [result, resultScopeFilter, filterRecordList]);

  const totalFilteredCount = filteredPrimary.length + filteredRelated.length;
  const hasActiveFilters =
    resultFilterText.trim() !== '' ||
    resultDbTypeFilter !== 'all' ||
    resultScopeFilter !== 'all' ||
    resultFilterType !== 'all' ||
    resultSourceFilter !== 'all' ||
    resultExtraKeyFilter !== 'all';

  return (
    <div className="space-y-6">
      <section
        aria-label={t('Discord ID Sorgu Formu', 'Discord ID Lookup Form')}
        className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6"
      >
        <div className="max-w-3xl">
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('Discord ID Sorgulama', 'Discord ID Lookup')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              '17-20 haneli Discord ID girin; sistem yalnızca sorgulanan hesaba ait kayıtları, Snowflake bilgilerini ve doğrulanmış çapraz eşleşmeleri düzenli biçimde getirir.',
              'Enter a 17–20 digit Discord ID to decode Snowflake metadata and retrieve verified identity-isolated records for that account.',
            )}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <label htmlFor="osint-search-input" className="sr-only">
              Discord ID
            </label>
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              id="osint-search-input"
              type="text"
              inputMode="numeric"
              value={query}
              onChange={(e) => onQueryChange(e.target.value)}
              placeholder={t('Örn. 104567890123456789 (17-20 haneli Discord ID)', 'e.g. 104567890123456789 (17–20 digit Discord ID)')}
              className="w-full rounded-lg border border-slate-300 bg-slate-50 py-2.5 pl-10 pr-4 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:bg-slate-950"
            />
          </div>
          <button
            type="submit"
            disabled={searching}
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap"
          >
            <Search className="h-4 w-4" />
            <span>{searching ? t('Aranıyor...', 'Searching...') : t('Sorgula', 'Lookup')}</span>
          </button>
        </form>

        {searchError && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{searchError}</span>
          </div>
        )}
      </section>

      {result && (
        <div className="space-y-6">
          <section
            aria-label={t('Discord Hesap Profili Özeti', 'Discord Account Profile Summary')}
            data-testid="discord-profile-summary"
            className="space-y-5 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6"
          >
            {/* Header Bar */}
            <div className="flex flex-col gap-4 border-b border-slate-200 pb-4 dark:border-slate-800 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3.5 sm:items-center">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-blue-600 dark:border-slate-700 dark:bg-slate-900 dark:text-blue-400">
                  <UserRound className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-display text-base font-bold text-slate-900 dark:text-slate-100">
                      {uniqueUsernames[0] || `${t('Discord Hesabı', 'Discord Account')} (${result.query.slice(-6)})`}
                    </h3>
                    <button
                      type="button"
                      onClick={() => void copyHeaderValue('id', result.query)}
                      title={t('Discord ID kopyala', 'Copy Discord ID')}
                      className="inline-flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-xs text-slate-600 transition-colors hover:border-blue-400 hover:text-blue-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:text-blue-400"
                    >
                      <span>#{result.query}</span>
                      {headerCopied === 'id' ? (
                        <Check className="h-3 w-3 text-emerald-500" />
                      ) : (
                        <Copy className="h-3 w-3 opacity-60" />
                      )}
                    </button>
                  </div>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {result.snowflake
                      ? `${t('Oluşturulma:', 'Created:')} ${formatTurkishDate(result.snowflake.createdAtIso)} (${result.snowflake.accountAge.years} ${t('yıl', 'yr')}, ${result.snowflake.accountAge.months} ${t('ay', 'mo')})`
                      : t('Snowflake bilgisi çözümlendi', 'Snowflake decoded')}
                  </p>
                </div>
              </div>

              <div className="flex flex-col items-start gap-1 text-xs sm:items-end">
                {allMatchedRecords.length > 0 ? (
                  <span className="font-semibold text-amber-600 dark:text-amber-400 tabular-nums">
                    {allMatchedRecords.length}{' '}
                    {t('Kayıtta Eşleşme Tespit Edildi', 'Exposure Records Detected')}
                  </span>
                ) : (
                  <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                    {t('Sızıntı / Eşleşme Tespit Edilmedi', 'No Exposure Records Detected')}
                  </span>
                )}
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                  <span>
                    {result.primaryMatches.length} {t('birincil eşleşme', 'direct')}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    {result.relatedMatches.length} {t('bağlantılı kayıt', 'linked')}
                  </span>
                </div>
              </div>
            </div>

            {/* Scannable Separated Attribute Panels (No Comma-Joined Walls) */}
            <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2 lg:grid-cols-3">
              <AttributePanel
                title={t('Kullanıcı Adları', 'Usernames')}
                items={uniqueUsernames}
                emptyText={t('Kullanıcı adı kaydı yok', 'No usernames recorded')}
                icon="user"
              />
              <AttributePanel
                title={t('E-posta Adresleri', 'Email Addresses')}
                items={uniqueEmails}
                emptyText={t('E-posta kaydı yok', 'No emails recorded')}
                icon="email"
                onItemAction={onPivotEmail}
                itemActionTitle={t('E-posta OSINT modülünde tara', 'Inspect in Email OSINT')}
              />
              <AttributePanel
                title={t('Telefon Numaraları', 'Phone Numbers')}
                items={uniquePhones}
                emptyText={t('Telefon numarası kaydı yok', 'No phone numbers recorded')}
                icon="phone"
              />
              <AttributePanel
                title={t('IP Adresleri', 'IP Addresses')}
                items={uniqueIps}
                emptyText={t('IP adresi kaydı yok', 'No IP addresses recorded')}
                icon="ip"
              />
              <AttributePanel
                title={t('Tespit Edilen Kaynak Etiketleri', 'Recorded Sources')}
                items={uniqueSources}
                emptyText={t('Ek kaynak etiketi yok', 'No source tags recorded')}
                icon="source"
              />
            </div>

            {/* Structured Dynamic Extra Fields */}
            {(extraFieldsSummary.length > 0 || uniqueNotes.length > 0) && (
              <div
                data-testid="dynamic-extra-summary"
                className="border-t border-slate-200 pt-4 dark:border-slate-800"
              >
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {t(
                    'Sorgulanan Hesaba Ait Ek Bilgiler & Nitelikler',
                    'Queried Account Attributes & Additional Details',
                  )}{' '}
                  ({extraFieldsSummary.length + (uniqueNotes.length > 0 ? 1 : 0)})
                </div>
                <div className="mt-3 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 lg:grid-cols-3">
                  {extraFieldsSummary.map((field) => {
                    const isExpanded = expandedExtraKeys.has(field.key);
                    const EXTRA_LIMIT = 4;
                    const visibleVals = isExpanded ? field.values : field.values.slice(0, EXTRA_LIMIT);
                    const hiddenCount = Math.max(0, field.values.length - EXTRA_LIMIT);

                    return (
                      <div
                        key={field.key}
                        className="flex flex-col justify-between rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-2.5 dark:border-slate-800 dark:bg-slate-900/50"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2 text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                            <span className="truncate">{field.key}</span>
                            {field.values.length > 1 && (
                              <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                                ({field.values.length})
                              </span>
                            )}
                          </div>
                          <ul className="mt-1.5 divide-y divide-slate-200/60 dark:divide-slate-800/70">
                            {visibleVals.map((val, vIdx) => (
                              <li
                                key={`${field.key}_${vIdx}`}
                                className="flex items-center justify-between gap-2 py-1 first:pt-0 last:pb-0"
                              >
                                <span className="min-w-0 break-all font-mono text-slate-900 dark:text-slate-100">
                                  {val}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => void copyHeaderValue(`ex_${field.key}_${vIdx}`, val)}
                                  aria-label={`Copy ${field.key}: ${val}`}
                                  className="shrink-0 rounded p-0.5 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                                >
                                  {headerCopied === `ex_${field.key}_${vIdx}` ? (
                                    <Check className="h-3 w-3 text-emerald-500" />
                                  ) : (
                                    <Copy className="h-3 w-3" />
                                  )}
                                </button>
                              </li>
                            ))}
                          </ul>
                        </div>

                        {(hiddenCount > 0 || isExpanded) && (
                          <button
                            type="button"
                            onClick={() => toggleExtraFieldExpand(field.key)}
                            className="mt-1.5 inline-flex items-center gap-1 self-start text-[11px] font-semibold text-blue-600 hover:underline dark:text-blue-400"
                          >
                            {isExpanded
                              ? t('Daralt', 'Collapse')
                              : t(`Tümünü Gör (+${hiddenCount})`, `Show All (+${hiddenCount})`)}
                          </button>
                        )}
                      </div>
                    );
                  })}

                  {uniqueNotes.length > 0 && (
                    <div className="rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-2.5 dark:border-slate-800 dark:bg-slate-900/50 sm:col-span-2 lg:col-span-3">
                      <div className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                        {t('Notlar / Ham Bilgiler', 'Notes / Additional Context')} ({uniqueNotes.length})
                      </div>
                      <ul className="mt-1.5 divide-y divide-slate-200/60 dark:divide-slate-800/70">
                        {uniqueNotes.slice(0, 8).map((note, idx) => (
                          <li key={idx} className="flex items-start justify-between gap-2 py-1.5 first:pt-0 last:pb-0">
                            <span className="break-words font-mono text-slate-900 dark:text-slate-100">{note}</span>
                            <button
                              type="button"
                              onClick={() => void copyHeaderValue(`note_${idx}`, note)}
                              aria-label="Copy note"
                              className="shrink-0 rounded p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
                            >
                              {headerCopied === `note_${idx}` ? (
                                <Check className="h-3 w-3 text-emerald-500" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>

          {result.snowflake && <SnowflakePanel snowflake={result.snowflake} />}

          {allMatchedRecords.length > 0 && (
            <section
              aria-label={t('Gelişmiş Arama Filtreleri', 'Advanced Search Filters')}
              data-testid="advanced-lookup-filters"
              className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-[#111827]"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/80 pb-3 dark:border-slate-800">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-slate-100">
                  <Database className="h-4 w-4 text-blue-500" />
                  <span>{t('Gelişmiş Sonuç Filtresi', 'Advanced Result Filter')}</span>
                  <span className="font-mono text-[11px] font-normal text-slate-500 dark:text-slate-400 tabular-nums">
                    ({t('Gösterilen:', 'Showing:')} {totalFilteredCount} / {allMatchedRecords.length})
                  </span>
                </div>

                {hasActiveFilters && (
                  <button
                    type="button"
                    onClick={resetAllFilters}
                    className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>{t('Filtreleri Sıfırla', 'Reset Filters')}</span>
                  </button>
                )}
              </div>

              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    {t('Veri Kategorisi:', 'Category:')}
                  </span>
                  <div
                    role="group"
                    aria-label={t('Veri kategorisine göre filtrele', 'Filter by data category')}
                    className="inline-flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-900/90"
                  >
                    {(
                      [
                        ['all', t('Tümü', 'All'), allMatchedRecords.length, 'active-blue'],
                        ['leak', 'Leak', dbTypeCounts.leak, 'active-rose'],
                        ['sizinti', t('Sızıntı', 'Breach'), dbTypeCounts.sizinti, 'active-amber'],
                        ['public_info', 'Public Info', dbTypeCounts.public_info, 'active-emerald'],
                      ] as const
                    ).map(([key, label, count, accent]) => {
                      const active = resultDbTypeFilter === key;
                      const activeCls =
                        accent === 'active-rose'
                          ? 'bg-rose-600 text-white shadow-xs'
                          : accent === 'active-amber'
                            ? 'bg-amber-600 text-white shadow-xs'
                            : accent === 'active-emerald'
                              ? 'bg-emerald-600 text-white shadow-xs'
                              : 'bg-blue-600 text-white shadow-xs';
                      return (
                        <button
                          key={key}
                          type="button"
                          aria-pressed={active}
                          data-testid={`db-type-filter-${key}`}
                          onClick={() => setResultDbTypeFilter(key)}
                          className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors whitespace-nowrap ${
                            active
                              ? activeCls
                              : 'text-slate-600 hover:bg-white/70 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white'
                          }`}
                        >
                          <span>{label}</span>
                          <span
                            className={`font-mono text-[10px] tabular-nums ${
                              active ? 'text-white/90' : 'text-slate-400 dark:text-slate-500'
                            }`}
                          >
                            ({count})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="relative flex-1 min-w-[220px] max-w-sm">
                  <label htmlFor="result-keyword-filter" className="sr-only">
                    {t('Sonuçlarda anlık anahtar kelime ara', 'Filter results by keyword')}
                  </label>
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                  <input
                    id="result-keyword-filter"
                    type="text"
                    value={resultFilterText}
                    onChange={(e) => setResultFilterText(e.target.value)}
                    placeholder={t(
                      'Anlık ara: e-posta, IP, telefon, HWID, not...',
                      'Instant filter: email, IP, phone, HWID, notes...',
                    )}
                    className="w-full rounded-lg border border-slate-300 bg-slate-50 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:bg-slate-950"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-600 dark:text-slate-300">
                <div className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <Filter className="h-3.5 w-3.5 text-blue-500" />
                  <span>{t('Detaylı Süzgeç:', 'Refinements:')}</span>
                </div>

                <div className="inline-flex flex-wrap rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800/80">
                  {(
                    [
                      ['all', t('Tüm İçerik', 'All Fields')],
                      ['has_email', t('E-postalı', 'With Email')],
                      ['has_contact', t('IP / Telefonlu', 'With IP / Phone')],
                      ['has_extra', t('Ek Alan / Notlu', 'With Extra / Notes')],
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      aria-pressed={resultFilterType === key}
                      onClick={() => setResultFilterType(key)}
                      className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors whitespace-nowrap ${
                        resultFilterType === key
                          ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                          : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <select
                  aria-label={t('Eşleşme kapsamına göre filtrele', 'Filter by match scope')}
                  value={resultScopeFilter}
                  onChange={(e) => setResultScopeFilter(e.target.value as MatchScopeFilter)}
                  className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                >
                  <option value="all">{t('Tüm Eşleşmeler (Doğrudan + Çapraz)', 'All Matches (Direct + Linked)')}</option>
                  <option value="primary">{t('Sadece Doğrudan Discord ID', 'Direct Discord ID Only')}</option>
                  <option value="related">{t('Sadece Çapraz Bağlantılar', 'Cross-Linked Only')}</option>
                </select>

                {uniqueSources.length > 0 && (
                  <select
                    aria-label={t('Kaynağa göre filtrele', 'Filter by source')}
                    value={resultSourceFilter}
                    onChange={(e) => setResultSourceFilter(e.target.value)}
                    className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                  >
                    <option value="all">{t('Tüm Kaynaklar', 'All Sources')}</option>
                    {uniqueSources.map((src) => (
                      <option key={src} value={src}>
                        {src}
                      </option>
                    ))}
                  </select>
                )}

                {extraFieldsSummary.length > 0 && (
                  <select
                    aria-label={t('Dinamik ek alana göre filtrele', 'Filter by dynamic attribute')}
                    value={resultExtraKeyFilter}
                    onChange={(e) => setResultExtraKeyFilter(e.target.value)}
                    className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                  >
                    <option value="all">
                      {lang === 'tr' ? 'Tüm Ek Alanlar' : 'All Extra Attributes'}
                    </option>
                    {extraFieldsSummary.map((field) => (
                      <option key={field.key} value={field.key}>
                        {field.key} ({field.values.length})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </section>
          )}

          {resultScopeFilter !== 'related' && (
            <section aria-label={t('Doğrudan Eşleşmeler', 'Direct Matches')} className="space-y-3">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('Doğrudan Discord ID Eşleşmeleri', 'Direct Discord ID Matches')} ({filteredPrimary.length})
              </h3>
              {filteredPrimary.length > 0 ? (
                <RecordTable
                  records={filteredPrimary}
                  onPivotQuery={(q) => onRunSearch(q)}
                  onPivotEmail={onPivotEmail}
                  testId="primary-matches-table"
                />
              ) : (
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <div>
                    <p className="font-medium text-slate-800 dark:text-slate-200">
                      {result.primaryMatches.length > 0
                        ? t('Uygulanan filtreyle eşleşen doğrudan kayıt bulunamadı.', 'No direct matches match the active filter.')
                        : t('Bu Discord ID için eşleşen kayıt bulunamadı.', 'No matching records found for this Discord ID.')}
                    </p>
                    <p className="mt-0.5 text-xs">
                      {result.primaryMatches.length > 0
                        ? t('Filtre metnini veya veri kategorisi seçimini temizleyebilirsiniz.', 'Clear the filter input or category toggle to view all matches.')
                        : t('Herhangi bir sızıntı veya ihlal kaydı tespit edilmedi.', 'No breach or leak exposure was detected.')}
                    </p>
                  </div>
                </div>
              )}
            </section>
          )}

          {resultScopeFilter !== 'primary' && (filteredRelated.length > 0 || (result.relatedMatches.length > 0 && hasActiveFilters)) && (
            <section aria-label={t('Bağlantılı Kayıtlar', 'Connected Records')} className="space-y-3">
              <div>
                <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {t('Bağlantılı Sızıntılar ve Çapraz Eşleşmeler', 'Connected Exposures & Cross-Matches')} ({filteredRelated.length})
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {t(
                    'Bu Discord ID ile doğrulanmış e-posta, telefon veya benzersiz kimlik üzerinden eşleşen diğer kayıtlar',
                    'Additional records correlated via verified email, phone, or unique identifiers linked to this Discord ID',
                  )}
                </p>
              </div>
              {filteredRelated.length > 0 ? (
                <RecordTable
                  records={filteredRelated}
                  onPivotQuery={(q) => onRunSearch(q)}
                  onPivotEmail={onPivotEmail}
                  testId="related-matches-table"
                />
              ) : (
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <div>
                    <p className="font-medium text-slate-800 dark:text-slate-200">
                      {t('Uygulanan filtreyle eşleşen bağlantılı kayıt bulunamadı.', 'No linked records match the active filter.')}
                    </p>
                    <p className="mt-0.5 text-xs">
                      {t('Veri kategorisi veya anahtar kelime filtresini sıfırlayarak tüm bağlantılı kayıtları görebilirsiniz.', 'Reset the category or keyword filter to see all connected records.')}
                    </p>
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
