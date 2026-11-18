import { useRef, useState, type ChangeEvent } from 'react';
import { FileUp, X, AlertCircle, CheckCircle2, Zap } from 'lucide-react';
import type { DatasetMeta, FieldMapping, IntelRecord } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import {
  apiAdminUploadAbort,
  apiAdminUploadChunk,
  apiAdminUploadComplete,
  apiAdminUploadInit,
} from '../utils/api';
import {
  normalizeRows,
  parseDatasetContent,
  parseDatasetSample,
  type ParsedTableResult,
} from '../utils/parser';

interface ImportModalProps {
  open: boolean;
  onClose: () => void;
  onImportComplete: (
    meta: DatasetMeta,
    records: IntelRecord[],
    onProgress?: (uploaded: number, total: number) => void,
  ) => Promise<void>;
  onRawUploadStarted?: (
    dataset: DatasetMeta,
    stats: { totalDatasets: number; totalRecords: number; totalUsers: number },
  ) => void;
}

const SAMPLE_PREVIEW_BYTES = 64 * 1024;
const RAW_CHUNK_BYTES = 2 * 1024 * 1024;
const DIRECT_PASTE_MAX_BYTES = 128 * 1024;

function formatByteVolume(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(2)} ${units[idx]}`;
}

export function ImportModal({
  open,
  onClose,
  onImportComplete,
  onRawUploadStarted,
}: ImportModalProps) {
  const { lang, t } = useI18n();
  const mappingFields: { key: keyof FieldMapping; label: string }[] = [
    { key: 'discordIdField', label: t('Discord ID Sütunu', 'Discord ID Column') },
    { key: 'emailField', label: t('E-posta Sütunu', 'Email Column') },
    { key: 'usernameField', label: t('Kullanıcı Adı Sütunu', 'Username Column') },
    { key: 'sourceField', label: t('Kaynak / Sızıntı Adı', 'Source / Breach Name') },
    { key: 'ipField', label: t('IP Adresi Sütunu', 'IP Address Column') },
    { key: 'phoneField', label: t('Telefon Sütunu', 'Phone Column') },
    { key: 'notesField', label: t('Notlar / Açıklama', 'Notes / Details') },
  ];
  const [inputMode, setInputMode] = useState<'file' | 'paste'>('file');
  const [datasetName, setDatasetName] = useState('');
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileSize, setFileSize] = useState(0);
  const [isSampledPreview, setIsSampledPreview] = useState(false);
  const [parsed, setParsed] = useState<ParsedTableResult | null>(null);
  const [mapping, setMapping] = useState<FieldMapping | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<{
    uploaded: number;
    total: number;
    unit: 'bytes' | 'rows';
  } | null>(null);

  const abortCtrlRef = useRef<AbortController | null>(null);
  const activeUploadIdRef = useRef<string | null>(null);

  if (!open) return null;

  const resetState = () => {
    setDatasetName('');
    setRawText('');
    setSelectedFile(null);
    setFileSize(0);
    setIsSampledPreview(false);
    setParsed(null);
    setMapping(null);
    setError(null);
    setSaving(false);
    setUploadProgress(null);
    abortCtrlRef.current = null;
    activeUploadIdRef.current = null;
  };

  const handleClose = () => {
    if (abortCtrlRef.current) {
      abortCtrlRef.current.abort();
    }
    if (activeUploadIdRef.current) {
      const idToAbort = activeUploadIdRef.current;
      activeUploadIdRef.current = null;
      void apiAdminUploadAbort(idToAbort);
    }
    resetState();
    onClose();
  };

  const runSampleParse = (
    sampleText: string,
    totalBytes: number,
    nameSuggestion?: string,
  ) => {
    setError(null);
    try {
      const result = parseDatasetSample(sampleText, nameSuggestion, totalBytes);
      setParsed(result);
      setMapping(result.suggestedMapping);
      if (nameSuggestion && !datasetName) {
        setDatasetName(nameSuggestion.replace(/\.[^.]+$/, ''));
      }
      setFileSize(totalBytes);
      setIsSampledPreview(totalBytes > sampleText.length);
    } catch (err) {
      setParsed(null);
      setMapping(null);
      setIsSampledPreview(false);
      setError(err instanceof Error ? err.message : t('Veri ayrıştırılamadı.', 'Failed to parse data.'));
    }
  };

  const handleFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setSelectedFile(file);
      setRawText('');
      setDatasetName(file.name.replace(/\.[^.]+$/, ''));
      // Read ONLY the first 64 KB for instant column/format detection — zero browser OOM on multi-GB files
      const headSlice = file.slice(0, SAMPLE_PREVIEW_BYTES);
      const sampleText = await headSlice.text();
      runSampleParse(sampleText, file.size, file.name);
    } catch {
      setError(t('Dosya okunamadı.', 'Could not read file.'));
    }
  };

  const handleParsePaste = () => {
    setSelectedFile(null);
    const totalBytes = new Blob([rawText]).size;
    const sample = rawText.length > SAMPLE_PREVIEW_BYTES ? rawText.slice(0, SAMPLE_PREVIEW_BYTES) : rawText;
    runSampleParse(sample, totalBytes, datasetName || undefined);
  };

  const handleConfirmImport = async () => {
    if (!parsed || !mapping) return;
    setSaving(true);
    setError(null);

    const finalName =
      datasetName.trim() ||
      `${t('Veri Seti', 'Dataset')} ${new Date().toLocaleTimeString(lang === 'tr' ? 'tr-TR' : 'en-US')}`;

    const useRawStreamPipeline =
      Boolean(selectedFile) || fileSize > DIRECT_PASTE_MAX_BYTES;

    if (useRawStreamPipeline) {
      const sourceBlob: Blob = selectedFile ?? new Blob([rawText], { type: 'text/plain;charset=utf-8' });
      const totalBytes = sourceBlob.size;
      const controller = new AbortController();
      abortCtrlRef.current = controller;
      setUploadProgress({ uploaded: 0, total: totalBytes, unit: 'bytes' });

      try {
        const initRes = await apiAdminUploadInit({
          name: finalName,
          format: parsed.format,
          sizeBytes: totalBytes,
          columns: parsed.columns,
          mapping,
        });
        const datasetId = initRes.dataset.id;
        activeUploadIdRef.current = datasetId;

        for (let offset = 0; offset < totalBytes; offset += RAW_CHUNK_BYTES) {
          if (controller.signal.aborted) {
            throw new Error(t('Yükleme iptal edildi.', 'Upload cancelled.'));
          }
          const slice = sourceBlob.slice(offset, Math.min(totalBytes, offset + RAW_CHUNK_BYTES));
          await apiAdminUploadChunk(datasetId, slice, offset, controller.signal);
          setUploadProgress({
            uploaded: Math.min(totalBytes, offset + slice.size),
            total: totalBytes,
            unit: 'bytes',
          });
        }

        const completed = await apiAdminUploadComplete(datasetId, {
          delimiter: parsed.delimiter,
          hasHeader: parsed.hasHeader,
          isHeterogeneous: parsed.isHeterogeneous,
          mapping,
        });

        activeUploadIdRef.current = null;
        abortCtrlRef.current = null;
        onRawUploadStarted?.(completed.dataset, completed.stats);
        resetState();
        onClose();
      } catch (err) {
        if (activeUploadIdRef.current) {
          const idToAbort = activeUploadIdRef.current;
          activeUploadIdRef.current = null;
          void apiAdminUploadAbort(idToAbort);
        }
        abortCtrlRef.current = null;
        setError(
          err instanceof Error
            ? err.message
            : t('Ham dosya sunucuya aktarılırken hata oluştu.', 'Failed to stream file to server.'),
        );
        setSaving(false);
        setUploadProgress(null);
      }
      return;
    }

    // Small paste text path (<= 128 KB): instant inline normalization & cloud backup sync
    try {
      const fullParsed = parseDatasetContent(rawText, datasetName || undefined);
      setUploadProgress({ uploaded: 0, total: fullParsed.rows.length, unit: 'rows' });
      const datasetId = `ds_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const records = normalizeRows(fullParsed.rows, mapping, datasetId, finalName);
      const meta: DatasetMeta = {
        id: datasetId,
        name: finalName,
        category: 'both',
        format: fullParsed.format,
        recordCount: records.length,
        columns: fullParsed.columns,
        mapping,
        importedAt: new Date().toISOString(),
        sizeBytes: fileSize || new Blob([rawText]).size,
      };
      await onImportComplete(meta, records, (uploaded, total) => {
        setUploadProgress({ uploaded, total, unit: 'rows' });
      });
      resetState();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Veri kaydedilirken hata oluştu.', 'Failed to save dataset.'));
      setSaving(false);
      setUploadProgress(null);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-xs"
    >
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
        <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-800">
          <div>
            <h2 id="import-modal-title" className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              {t('Veri Deposu İçe Aktar', 'Import Dataset')}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              {t(
                'Herhangi bir boyuttaki dosyayı seçin; ham dosya doğrudan sunucuya aktarılıp arka planda sınırsız olarak analiz edilir ve tüm sorgularda taranır.',
                'Select a file of any size; raw chunks upload directly to the server and are analyzed in the background with no row limits.',
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            aria-label={t('İçe aktarma penceresini kapat', 'Close import modal')}
            className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="inline-flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80 self-end">
              <button
                type="button"
                onClick={() => {
                  setInputMode('file');
                  setError(null);
                }}
                className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  inputMode === 'file'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                }`}
              >
                {t('Dosyadan', 'From File')}
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputMode('paste');
                  setSelectedFile(null);
                  setError(null);
                }}
                className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  inputMode === 'paste'
                    ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                }`}
              >
                {t('Metin Yapıştır', 'Paste Text')}
              </button>
            </div>

            <div>
              <label htmlFor="dataset-name-input" className="block text-xs font-medium text-slate-600 dark:text-slate-400">
                {t('Depo Adı (Yalnızca Admin Görür)', 'Dataset Name (Admin Only)')}
              </label>
              <input
                id="dataset-name-input"
                type="text"
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                placeholder={t('Örn. Discord_Sizinti_2024', 'e.g. Discord_Breach_2024')}
                className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          {inputMode === 'file' ? (
            <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-slate-50/70 px-6 py-8 text-center transition-colors hover:border-blue-500 hover:bg-blue-50/30 dark:border-slate-700 dark:bg-slate-900/50 dark:hover:border-blue-500 dark:hover:bg-slate-800/40">
              <FileUp className="h-7 w-7 text-slate-400 dark:text-slate-500" />
              <span className="mt-2 text-sm font-medium text-slate-800 dark:text-slate-200">
                {selectedFile
                  ? `${selectedFile.name} (${formatByteVolume(selectedFile.size)})`
                  : t('Dosya seçin veya buraya sürükleyin', 'Choose a file or drop it here')}
              </span>
              <span className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {t('Desteklenen formatlar: .json, .jsonl, .ndjson, .csv, .txt, .sql, .log (Boyut / Satır sınırı yok)', 'Supported formats: .json, .jsonl, .ndjson, .csv, .txt, .sql, .log (Unlimited size & rows)')}
              </span>
              <input
                type="file"
                accept=".json,.jsonl,.ndjson,.csv,.txt,.tsv,.sql,.log"
                onChange={handleFileChange}
                className="sr-only"
              />
            </label>
          ) : (
            <div className="space-y-2.5">
              <label htmlFor="paste-data-textarea" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                {t('Ham Veri İçeriği (JSON, CSV, SQL veya satır bazlı id:eposta:kullanici / ULP)', 'Raw Data (JSON, CSV, SQL, or line-based id:email:username / ULP)')}
              </label>
              <textarea
                id="paste-data-textarea"
                rows={6}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder={'104567890123456789:ornek@example.test:kullanici1:KaynakA\n452910384756192012:diger@demo.invalid:kullanici2:KaynakB'}
                className="w-full rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              />
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={handleParsePaste}
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                >
                  {t('Veriyi Çözümle ve Önizle', 'Parse & Preview')}
                </button>
              </div>
            </div>
          )}

          {error && (
            <div role="alert" className="flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {parsed && mapping && (
            <div className="space-y-4 border-t border-slate-200 pt-5 dark:border-slate-800">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                  <span>
                    {isSampledPreview
                      ? `${formatByteVolume(fileSize)} ${t('ham dosya hazır', 'raw file ready')} · ${parsed.columns.length} ${t('sütun algılandı', 'columns detected')} (${parsed.format.toUpperCase()})`
                      : `${parsed.rows.length.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} ${t('satır ve', 'rows and')} ${parsed.columns.length} ${t('sütun ayrıştırıldı', 'columns parsed')} (${parsed.format.toUpperCase()})`}
                  </span>
                </div>
                {(selectedFile || fileSize > DIRECT_PASTE_MAX_BYTES) && (
                  <span className="inline-flex items-center gap-1 rounded bg-blue-500/10 px-2 py-0.5 text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                    <Zap className="h-3 w-3" />
                    <span>{t('Hızlı Akış + Arka Plan Analiz', 'Fast Stream + Background Analysis')}</span>
                  </span>
                )}
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  {t('Sütun Eşleştirme', 'Column Mapping')}
                </h3>
                <div className="mt-2.5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {mappingFields.map((field) => (
                    <div key={field.key}>
                      <label
                        htmlFor={`map-${field.key}`}
                        className="block text-xs text-slate-500 dark:text-slate-400"
                      >
                        {field.label}
                      </label>
                      <select
                        id={`map-${field.key}`}
                        value={mapping[field.key] || ''}
                        onChange={(e) =>
                          setMapping({
                            ...mapping,
                            [field.key]: e.target.value || null,
                          })
                        }
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                      >
                        <option value="">{t('Eşleştirme yok', 'None')}</option>
                        {parsed.columns.map((col) => (
                          <option key={col} value={col}>
                            {col}
                          </option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  {t('İlk 3 Satır Önizlemesi', 'First 3 Rows Preview')}
                </h3>
                <div className="mt-2 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                      <tr>
                        {parsed.columns.slice(0, 6).map((col) => (
                          <th key={col} className="px-3 py-2 font-medium whitespace-nowrap">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                      {parsed.rows.slice(0, 3).map((row, idx) => (
                        <tr key={idx} className="bg-white dark:bg-[#111827]">
                          {parsed.columns.slice(0, 6).map((col) => (
                            <td key={col} className="max-w-[180px] truncate px-3 py-2 font-mono text-slate-700 dark:text-slate-300">
                              {row[col] || '—'}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 px-6 py-4 dark:border-slate-800">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {saving && uploadProgress && uploadProgress.total > 0 && (
              <span className="font-mono">
                {uploadProgress.unit === 'bytes'
                  ? `${formatByteVolume(uploadProgress.uploaded)} / ${formatByteVolume(uploadProgress.total)} (${Math.min(100, Math.round((uploadProgress.uploaded / uploadProgress.total) * 100))}%)`
                  : `${uploadProgress.uploaded.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} / ${uploadProgress.total.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} (${Math.min(100, Math.round((uploadProgress.uploaded / uploadProgress.total) * 100))}%)`}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleClose}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            >
              {t('İptal', 'Cancel')}
            </button>
            <button
              type="button"
              disabled={!parsed || saving}
              onClick={handleConfirmImport}
              className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? t('Sunucuya Aktarılıyor...', 'Uploading Raw File...') : t('Veriyi İçe Aktar', 'Import Data')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
