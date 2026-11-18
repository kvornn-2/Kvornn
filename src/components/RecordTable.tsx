import { useEffect, useState } from 'react';
import { Check, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import type { DatabaseSourceType, IntelRecord } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { classifyRecordDatabaseType, isTimestampLikeValue } from '../utils/search';

interface RecordTableProps {
  records: IntelRecord[];
  onPivotQuery: (query: string) => void;
  onPivotEmail?: (email: string) => void;
  testId?: string;
}

const DB_TYPE_STYLES: Record<DatabaseSourceType, { tr: string; en: string; cls: string }> = {
  leak: {
    tr: 'Leak',
    en: 'Leak',
    cls: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  sizinti: {
    tr: 'Sızıntı',
    en: 'Breach',
    cls: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  public_info: {
    tr: 'Public Info',
    en: 'Public Info',
    cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
};

const PAGE_STEP = 50;
const EXTRA_PREVIEW_LIMIT = 4;

export function RecordTable({
  records,
  onPivotQuery,
  onPivotEmail,
  testId,
}: RecordTableProps) {
  const { lang, t } = useI18n();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(PAGE_STEP);
  const [expandedExtraIds, setExpandedExtraIds] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    setVisibleCount(PAGE_STEP);
    setExpandedExtraIds(new Set());
  }, [records]);

  const handleCopy = async (key: string, value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1400);
    } catch {
      // Ignore clipboard errors
    }
  };

  const toggleExtraExpand = (recId: string) => {
    setExpandedExtraIds((prev) => {
      const next = new Set(prev);
      if (next.has(recId)) next.delete(recId);
      else next.add(recId);
      return next;
    });
  };

  const shownRecords = records.length > visibleCount ? records.slice(0, visibleCount) : records;
  const remaining = Math.max(0, records.length - shownRecords.length);

  return (
    <div
      data-testid={testId}
      className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]"
    >
      {/* Mobile-friendly structured card stack */}
      <div className="divide-y divide-slate-200 dark:divide-slate-800 md:hidden">
        {shownRecords.map((rec) => {
          const extraEntries = Object.entries(rec.extra || {}).filter(([, v]) => String(v || '').trim() !== '');
          const dbType = classifyRecordDatabaseType(rec);
          const typeMeta = DB_TYPE_STYLES[dbType];
          const cleanPhone = rec.phone && !isTimestampLikeValue(rec.phone) ? rec.phone.trim() : '';
          const isExtraExpanded = expandedExtraIds.has(rec.id);
          const visibleExtra = isExtraExpanded ? extraEntries : extraEntries.slice(0, EXTRA_PREVIEW_LIMIT);

          return (
            <article key={rec.id} className="space-y-3 p-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 font-mono">
                  {rec.discordId ? (
                    <>
                      <button
                        type="button"
                        onClick={() => onPivotQuery(rec.discordId)}
                        className="font-semibold text-blue-600 hover:underline dark:text-blue-400"
                      >
                        {rec.discordId}
                      </button>
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-mob-id`, rec.discordId)}
                        aria-label={`Copy Discord ID: ${rec.discordId}`}
                        className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        {copiedKey === `${rec.id}-mob-id` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </>
                  ) : (
                    <span className="font-medium text-slate-500 dark:text-slate-400">
                      {t('Eşleşen Kayıt', 'Linked Record')}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  {rec.source && (
                    <span className="font-medium text-slate-700 dark:text-slate-300">{rec.source}</span>
                  )}
                  <span
                    className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeMeta.cls}`}
                  >
                    {lang === 'tr' ? typeMeta.tr : typeMeta.en}
                  </span>
                </div>
              </div>

              <dl className="divide-y divide-slate-100 rounded-lg border border-slate-200/80 bg-slate-50/50 dark:divide-slate-800/80 dark:border-slate-800 dark:bg-slate-900/40">
                {rec.email && (
                  <div className="flex items-center justify-between gap-2 px-3 py-2">
                    <dt className="shrink-0 text-[11px] text-slate-500 dark:text-slate-400">
                      {t('E-posta', 'Email')}
                    </dt>
                    <dd className="flex min-w-0 items-center gap-1.5 font-mono text-slate-900 dark:text-slate-100">
                      {onPivotEmail ? (
                        <button
                          type="button"
                          onClick={() => onPivotEmail(rec.email)}
                          className="truncate font-medium hover:text-blue-600 hover:underline dark:hover:text-blue-400"
                        >
                          {rec.email}
                        </button>
                      ) : (
                        <span className="truncate font-medium">{rec.email}</span>
                      )}
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-mob-email`, rec.email)}
                        aria-label={`Copy email: ${rec.email}`}
                        className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        {copiedKey === `${rec.id}-mob-email` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </dd>
                  </div>
                )}

                {rec.username && (
                  <div className="flex items-center justify-between gap-2 px-3 py-2">
                    <dt className="shrink-0 text-[11px] text-slate-500 dark:text-slate-400">
                      {t('Kullanıcı', 'Username')}
                    </dt>
                    <dd className="flex min-w-0 items-center gap-1.5 font-mono text-slate-900 dark:text-slate-100">
                      <span className="truncate">{rec.username}</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-mob-user`, rec.username)}
                        aria-label={`Copy username: ${rec.username}`}
                        className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        {copiedKey === `${rec.id}-mob-user` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </dd>
                  </div>
                )}

                {cleanPhone && (
                  <div className="flex items-center justify-between gap-2 px-3 py-2">
                    <dt className="shrink-0 text-[11px] text-slate-500 dark:text-slate-400">
                      {t('Telefon', 'Phone')}
                    </dt>
                    <dd className="flex min-w-0 items-center gap-1.5 font-mono text-slate-900 dark:text-slate-100">
                      <span className="truncate">{cleanPhone}</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-mob-phone`, cleanPhone)}
                        aria-label={`Copy phone: ${cleanPhone}`}
                        className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        {copiedKey === `${rec.id}-mob-phone` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </dd>
                  </div>
                )}

                {rec.ip && (
                  <div className="flex items-center justify-between gap-2 px-3 py-2">
                    <dt className="shrink-0 text-[11px] text-slate-500 dark:text-slate-400">IP</dt>
                    <dd className="flex min-w-0 items-center gap-1.5 font-mono text-slate-900 dark:text-slate-100">
                      <span className="truncate">{rec.ip}</span>
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-mob-ip`, rec.ip)}
                        aria-label={`Copy IP: ${rec.ip}`}
                        className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200/70 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                      >
                        {copiedKey === `${rec.id}-mob-ip` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </dd>
                  </div>
                )}
              </dl>

              {rec.notes && (
                <div className="rounded-lg border border-slate-200/70 bg-slate-50/40 px-3 py-2 text-[11px] text-slate-700 dark:border-slate-800 dark:bg-slate-900/30 dark:text-slate-300">
                  <span className="font-semibold text-slate-500 dark:text-slate-400">{t('Not:', 'Notes:')} </span>
                  <span className="break-words font-mono">{rec.notes}</span>
                </div>
              )}

              {visibleExtra.length > 0 && (
                <div className="space-y-1.5">
                  <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                    {visibleExtra.map(([k, v]) => (
                      <div
                        key={k}
                        className="flex items-center justify-between gap-2 rounded border border-slate-200/70 bg-slate-50/40 px-2.5 py-1.5 text-[11px] dark:border-slate-800/80 dark:bg-slate-900/30"
                      >
                        <span className="truncate text-slate-500 dark:text-slate-400">{k}</span>
                        <span className="truncate font-mono text-slate-900 dark:text-slate-100">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                  {extraEntries.length > EXTRA_PREVIEW_LIMIT && (
                    <button
                      type="button"
                      onClick={() => toggleExtraExpand(rec.id)}
                      className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-600 hover:underline dark:text-blue-400"
                    >
                      {isExtraExpanded ? (
                        <>
                          <ChevronUp className="h-3 w-3" />
                          <span>{t('Ek alanları gizle', 'Hide extra fields')}</span>
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-3 w-3" />
                          <span>
                            +{extraEntries.length - EXTRA_PREVIEW_LIMIT} {t('ek alan daha', 'more fields')}
                          </span>
                        </>
                      )}
                    </button>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </div>

      {/* Desktop clean scannable table */}
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
            <tr>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">Discord ID</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('E-posta Adresi', 'Email Address')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Kullanıcı Adı', 'Username')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Tür / Kaynak', 'Type / Source')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Bağlantı & Ek Bilgiler', 'Contact & Details')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {shownRecords.map((rec) => {
              const extraEntries = Object.entries(rec.extra || {}).filter(([, v]) => String(v || '').trim() !== '');
              const dbType = classifyRecordDatabaseType(rec);
              const typeMeta = DB_TYPE_STYLES[dbType];
              const cleanPhone = rec.phone && !isTimestampLikeValue(rec.phone) ? rec.phone.trim() : '';
              const isExtraExpanded = expandedExtraIds.has(rec.id);
              const visibleExtra = isExtraExpanded ? extraEntries : extraEntries.slice(0, EXTRA_PREVIEW_LIMIT);

              return (
                <tr
                  key={rec.id}
                  className="transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/30"
                >
                  <td className="px-4 py-3 align-top font-mono whitespace-nowrap">
                    {rec.discordId ? (
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onPivotQuery(rec.discordId)}
                          title={t('Bu Discord ID ile sorgula', 'Lookup this Discord ID')}
                          className="font-medium text-blue-600 hover:underline dark:text-blue-400"
                        >
                          {rec.discordId}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopy(`${rec.id}-id`, rec.discordId)}
                          aria-label={`Copy Discord ID: ${rec.discordId}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                        >
                          {copiedKey === `${rec.id}-id` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top font-mono whitespace-nowrap">
                    {rec.email ? (
                      <div className="flex items-center gap-1.5">
                        {onPivotEmail ? (
                          <button
                            type="button"
                            onClick={() => onPivotEmail(rec.email)}
                            title={t('Bu e-postayı E-posta OSINT modülünde tara', 'Scan this email in Email OSINT')}
                            className="font-medium text-slate-900 hover:text-blue-600 hover:underline dark:text-slate-100 dark:hover:text-blue-400"
                          >
                            {rec.email}
                          </button>
                        ) : (
                          <span className="font-medium text-slate-900 dark:text-slate-100">{rec.email}</span>
                        )}
                        <button
                          type="button"
                          onClick={() => handleCopy(`${rec.id}-email`, rec.email)}
                          aria-label={`Copy email: ${rec.email}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                        >
                          {copiedKey === `${rec.id}-email` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top whitespace-nowrap text-slate-800 dark:text-slate-200">
                    {rec.username ? (
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-medium">{rec.username}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(`${rec.id}-user`, rec.username)}
                          aria-label={`Copy username: ${rec.username}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                        >
                          {copiedKey === `${rec.id}-user` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300 whitespace-nowrap">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span
                        className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeMeta.cls}`}
                      >
                        {lang === 'tr' ? typeMeta.tr : typeMeta.en}
                      </span>
                      {rec.source && (
                        <span className="font-medium text-slate-900 dark:text-slate-100">{rec.source}</span>
                      )}
                    </div>
                  </td>

                  <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300">
                    <div className="space-y-1.5">
                      {rec.ip && (
                        <div className="flex items-center gap-1.5 font-mono">
                          <span className="text-slate-400">IP:</span>
                          <span className="text-slate-900 dark:text-slate-100">{rec.ip}</span>
                          <button
                            type="button"
                            onClick={() => handleCopy(`${rec.id}-ip`, rec.ip)}
                            aria-label={`Copy IP: ${rec.ip}`}
                            className="rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                          >
                            {copiedKey === `${rec.id}-ip` ? (
                              <Check className="h-3 w-3 text-emerald-500" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      )}
                      {cleanPhone && (
                        <div className="flex items-center gap-1.5 font-mono">
                          <span className="text-slate-400">{t('Tel:', 'Phone:')}</span>
                          <span className="text-slate-900 dark:text-slate-100">{cleanPhone}</span>
                          <button
                            type="button"
                            onClick={() => handleCopy(`${rec.id}-phone`, cleanPhone)}
                            aria-label={`Copy phone: ${cleanPhone}`}
                            className="rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                          >
                            {copiedKey === `${rec.id}-phone` ? (
                              <Check className="h-3 w-3 text-emerald-500" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      )}
                      {rec.notes && (
                        <div className="max-w-md break-words text-[11px] text-slate-600 dark:text-slate-400">
                          {rec.notes}
                        </div>
                      )}
                      {visibleExtra.length > 0 && (
                        <div className="space-y-1">
                          <div className="grid grid-cols-1 gap-1 text-[11px] lg:grid-cols-2">
                            {visibleExtra.map(([k, v]) => (
                              <div
                                key={k}
                                className="flex items-center justify-between gap-2 rounded border border-slate-200/70 bg-slate-50/70 px-2 py-0.5 dark:border-slate-800 dark:bg-slate-900/50"
                              >
                                <span className="truncate text-slate-500 dark:text-slate-400">{k}:</span>
                                <span className="truncate font-mono text-slate-800 dark:text-slate-200">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                          {extraEntries.length > EXTRA_PREVIEW_LIMIT && (
                            <button
                              type="button"
                              onClick={() => toggleExtraExpand(rec.id)}
                              className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-600 hover:underline dark:text-blue-400"
                            >
                              {isExtraExpanded ? (
                                <>
                                  <ChevronUp className="h-3 w-3" />
                                  <span>{t('Daralt', 'Collapse')}</span>
                                </>
                              ) : (
                                <>
                                  <ChevronDown className="h-3 w-3" />
                                  <span>
                                    +{extraEntries.length - EXTRA_PREVIEW_LIMIT} {t('ek alan', 'more')}
                                  </span>
                                </>
                              )}
                            </button>
                          )}
                        </div>
                      )}
                      {!rec.ip && !cleanPhone && !rec.notes && extraEntries.length === 0 && (
                        <span className="text-slate-400">—</span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {remaining > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 bg-slate-50/80 px-4 py-2.5 text-xs dark:border-slate-800 dark:bg-slate-900/50">
          <span className="text-slate-600 dark:text-slate-400 tabular-nums">
            {t(
              `Toplam ${records.length} kaydın ${shownRecords.length} tanesi gösteriliyor`,
              `Showing ${shownRecords.length} of ${records.length} records`,
            )}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setVisibleCount((prev) => prev + PAGE_STEP)}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            >
              +{Math.min(PAGE_STEP, remaining)} {t('Daha Göster', 'Show More')}
            </button>
            <button
              type="button"
              onClick={() => setVisibleCount(records.length)}
              className="rounded-md border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-[11px] font-semibold text-blue-700 hover:bg-blue-500/20 dark:text-blue-300"
            >
              {t(`Tümünü Göster (${records.length})`, `Show All (${records.length})`)}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
