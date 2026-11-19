import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import {
  Database,
  Sliders,
  Users,
  Upload,
  Trash2,
  Ban,
  CheckCircle2,
  AlertCircle,
  Table2,
  Search,
  MailCheck,
  ShieldAlert,
  UserX,
  Cloud,
  Pencil,
  Download,
  FileUp,
  FileSpreadsheet,
  FileJson,
  ShieldOff,
  X,
  KeyRound,
  RefreshCw,
  Copy,
  ShieldCheck,
} from 'lucide-react';
import { DatasetEditorModal } from './DatasetEditorModal';
import type {
  AdminOversightData,
  AdminUserRow,
  BlockedRegistrationAttempt,
  DatasetMeta,
  IntelRecord,
  QueryAuditLog,
  QueryBlacklist,
  RoleConfigMap,
  RolePermissions,
  StandardRole,
} from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import {
  ApiError,
  apiAdminAddBlacklist,
  apiAdminCloudAuthorize,
  apiAdminDatabaseRecords,
  apiAdminExportCloudSnapshot,
  apiAdminExportDataset,
  apiAdminImportCloudSnapshot,
  apiAdminKickAllUsers,
  apiAdminOverview,
  apiAdminRemoveBlacklist,
  apiDeleteDataset,
  apiLoadSyntheticDataset,
  apiManagerBanAdmin,
  apiManagerBanAdminIp,
  apiManagerResetAdminKey,
  apiUpdateRoleConfig,
  apiUpdateUser,
} from '../utils/api';
import {
  clearAllMembersFromFirestore,
  connectAdminGoogleAccount,
  deleteDatasetFromFirestore,
  getConnectedCloudAdminEmail,
  isCloudRootAdminConnected,
  type AutoSyncResult,
  type CloudBackupSnapshot,
} from '../utils/firestoreSync';
import { formatTurkishDate } from '../utils/snowflake';

interface AdminViewProps {
  onOpenImport: () => void;
  onStatsChanged: () => Promise<void>;
  onUnauthorizedAdmin: () => void;
  refreshSignal?: number;
  cloudSyncStatus?: 'idle' | 'syncing' | 'synced' | 'needs_google' | 'error';
  cloudSyncDetail?: string | null;
  cloudSyncError?: string | null;
  onRequestCloudSync?: (opts?: {
    pushRoles?: boolean;
    restoreMissing?: boolean;
    forceDatasetIds?: string[];
  }) => Promise<{ ok: boolean; error?: string; result?: AutoSyncResult } | void>;
}

const STANDARD_ROLES: StandardRole[] = ['Üye', 'Destekçi', 'İşletme'];

export function AdminView({
  onOpenImport,
  onStatsChanged,
  onUnauthorizedAdmin,
  refreshSignal = 0,
  cloudSyncStatus = 'idle',
  cloudSyncDetail = null,
  cloudSyncError = null,
  onRequestCloudSync,
}: AdminViewProps) {
  const { lang, t } = useI18n();
  const [adminVerified, setAdminVerified] = useState(false);
  const [isRootManager, setIsRootManager] = useState(false);
  const [adminOversight, setAdminOversight] = useState<AdminOversightData | null>(null);
  const [subTab, setSubTab] = useState<'datasets' | 'roles' | 'users' | 'database' | 'blacklist' | 'manager'>('datasets');
  const [datasets, setDatasets] = useState<DatasetMeta[]>([]);
  const [roles, setRoles] = useState<RoleConfigMap | null>(null);
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [blockedAttempts, setBlockedAttempts] = useState<BlockedRegistrationAttempt[]>([]);
  const [queryLogs, setQueryLogs] = useState<QueryAuditLog[]>([]);
  const [blacklist, setBlacklist] = useState<QueryBlacklist>({ discordIds: [], emails: [] });
  const [blacklistInput, setBlacklistInput] = useState('');
  const [blacklistBusy, setBlacklistBusy] = useState(false);
  const [generatedAdminKey, setGeneratedAdminKey] = useState<string | null>(null);
  const [customAdminKeyInput, setCustomAdminKeyInput] = useState('');
  const [adminBanReasonInput, setAdminBanReasonInput] = useState('');
  const [managerBusy, setManagerBusy] = useState(false);
  const [copiedNewKey, setCopiedNewKey] = useState(false);
  const [dbRecords, setDbRecords] = useState<IntelRecord[]>([]);
  const [dbTotal, setDbTotal] = useState(0);
  const [dbSearch, setDbSearch] = useState('');
  const [dbDatasetFilter, setDbDatasetFilter] = useState('');
  const [dbLoading, setDbLoading] = useState(false);

  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [banTargetId, setBanTargetId] = useState<string | null>(null);
  const [banReason, setBanReason] = useState('');
  const [kickConfirmOpen, setKickConfirmOpen] = useState(false);
  const [cloudConnected, setCloudConnected] = useState<boolean>(() => isCloudRootAdminConnected());
  const [cloudBusy, setCloudBusy] = useState(false);
  const [vaultBusy, setVaultBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const restoreInputRef = useRef<HTMLInputElement | null>(null);
  const [editingDataset, setEditingDataset] = useState<DatasetMeta | null>(null);

  const queryTypeLabel = (qt: QueryAuditLog['queryType']) => {
    if (qt === 'id_lookup') return t('ID Sorgu', 'ID Lookup');
    if (qt === 'email_osint') return t('E-posta OSINT', 'Email OSINT');
    if (qt === 'ip_lookup') return t('IP Sorgu', 'IP Lookup');
    return t('Toplu Sorgu', 'Bulk Lookup');
  };

  const loadOverview = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await apiAdminOverview();
      setAdminVerified(true);
      setIsRootManager(Boolean(data.isRootManager));
      setAdminOversight(data.isRootManager && data.adminOversight ? data.adminOversight : null);
      setDatasets(data.datasets);
      setRoles(data.roles);
      setUsers(data.users);
      setBlockedAttempts(data.blockedAttempts || []);
      setQueryLogs(data.queryLogs);
      if (data.blacklist) setBlacklist(data.blacklist);
      setDbRecords(data.recordsSample);
      setDbTotal(data.stats.totalRecords);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setAdminVerified(false);
        onUnauthorizedAdmin();
        return;
      }
      if (!silent) {
        setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Yönetici verileri alınamadı.', 'Failed to load admin data.') });
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, [t, onUnauthorizedAdmin]);

  useEffect(() => {
    loadOverview(false);
  }, [loadOverview, refreshSignal]);

  const hasPendingIngestion = datasets.some(
    (d) => d.ingestionStatus === 'uploading' || d.ingestionStatus === 'analyzing',
  );

  useEffect(() => {
    if (!hasPendingIngestion) return;
    const timer = window.setInterval(() => {
      void loadOverview(true);
      void onStatsChanged();
    }, 2500);
    return () => window.clearInterval(timer);
  }, [hasPendingIngestion, loadOverview, onStatsChanged]);

  const handleLoadSynthetic = async () => {
    setFeedback(null);
    try {
      await apiLoadSyntheticDataset();
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t('Sentetik test veri seti başarıyla eklendi.', 'Synthetic test dataset added successfully.') });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Yükleme başarısız.', 'Upload failed.') });
    }
  };

  const handleDeleteDataset = async (id: string) => {
    setFeedback(null);
    try {
      await apiDeleteDataset(id);
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (isRootManager) void deleteDatasetFromFirestore(id).catch(() => {});
      setFeedback({ type: 'ok', text: t('Veri deposu silindi.', 'Dataset deleted.') });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Silme işlemi başarısız.', 'Delete failed.') });
    }
  };

  const handleRoleFieldChange = (
    role: StandardRole,
    key: keyof RolePermissions,
    value: number | boolean,
  ) => {
    if (!roles) return;
    setRoles({
      ...roles,
      [role]: {
        ...roles[role],
        [key]: value,
      },
    });
  };

  const handleSaveRole = async (role: StandardRole) => {
    if (!roles) return;
    setFeedback(null);
    try {
      const res = await apiUpdateRoleConfig(role, roles[role]);
      setRoles(res.roles);
      if (isRootManager) void onRequestCloudSync?.({ pushRoles: true, restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${role} rolünün yetki ve hakları güncellendi.`, `Permissions for ${role} updated.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Rol kaydedilemedi.', 'Failed to save role.') });
    }
  };

  const handleChangeUserRole = async (userId: string, nextRole: StandardRole) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, { role: nextRole });
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)));
      if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${res.user.username} kullanıcısının rolü ${nextRole} yapıldı.`, `User ${res.user.username} role set to ${nextRole}.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Kullanıcı güncellenemedi.', 'Failed to update user.') });
    }
  };

  const handleApproveEmail = async (userId: string) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, { approveEmail: true });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)),
      );
      if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${res.user.username} e-posta adresi onaylandı.`, `Email approved for ${res.user.username}.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Onaylama başarısız.', 'Approval failed.') });
    }
  };

  const handleConfirmBan = async (userId: string, banned: boolean) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, {
        banned,
        banReason: banned ? banReason : '',
      });
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)));
      setBanTargetId(null);
      setBanReason('');
      if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({
        type: 'ok',
        text: banned
          ? t(`${res.user.username} yasaklandı.`, `${res.user.username} has been banned.`)
          : t(`${res.user.username} kullanıcısının yasağı kaldırıldı.`, `Ban lifted for ${res.user.username}.`),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('İşlem başarısız.', 'Action failed.') });
    }
  };

  const handleKickAllUsers = async (clearAccounts: boolean) => {
    setFeedback(null);
    try {
      const res = await apiAdminKickAllUsers(clearAccounts);
      setKickConfirmOpen(false);
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (clearAccounts && isRootManager) {
        void clearAllMembersFromFirestore().catch(() => {});
      }
      setFeedback({
        type: 'ok',
        text: clearAccounts
          ? t(
              `Tüm üye hesapları (${res.kickedCount}) ve aktif oturumlar temizlendi. Yalnızca Admin aktif kaldı.`,
              `All member accounts (${res.kickedCount}) and active sessions were cleared. Only Admin remains.`,
            )
          : t(
              'Tüm kullanıcı oturumları sonlandırıldı. Yalnızca Admin oturumu aktif kaldı.',
              'All non-admin user sessions were terminated. Only Admin remains active.',
            ),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('İşlem başarısız.', 'Action failed.') });
    }
  };

  const handleConnectCloudAdmin = async () => {
    setFeedback(null);
    setCloudBusy(true);
    try {
      const res = await connectAdminGoogleAccount(apiAdminCloudAuthorize);
      setCloudConnected(res.authorized);
      const syncRes = await onRequestCloudSync?.({ restoreMissing: true });
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (syncRes && 'ok' in syncRes && !syncRes.ok) {
        setFeedback({
          type: 'err',
          text: syncRes.error || t('Google hesabı bağlandı ancak bulut eşitlemesi tamamlanamadı.', 'Google linked but cloud sync failed.'),
        });
      } else {
        const synced = syncRes && 'result' in syncRes ? syncRes.result : undefined;
        setFeedback({
          type: 'ok',
          text: synced && (synced.restoredDatasets > 0 || synced.restoredUsers > 0 || synced.uploadedDatasets > 0)
            ? t(
                `Google hesabı bağlandı (${res.email}) · Geri yüklenen: +${synced.restoredDatasets} depo, +${synced.restoredRecords} kayıt, +${synced.restoredUsers} üye · Buluta yedeklenen: +${synced.uploadedDatasets} depo.`,
                `Google linked (${res.email}) · Restored: +${synced.restoredDatasets} datasets, +${synced.restoredRecords} records, +${synced.restoredUsers} users · Backed up: +${synced.uploadedDatasets} datasets.`,
              )
            : t(
                `Yönetici Google hesabı bulut kasasına bağlandı ve eşitlendi (${res.email}).`,
                `Manager Google account connected and synced with cloud vault (${res.email}).`,
              ),
        });
      }
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Bulut bağlantısı doğrulanamadı.', 'Cloud authorization failed.'),
      });
    } finally {
      setCloudBusy(false);
    }
  };

  const handleManualCloudSync = async () => {
    setFeedback(null);
    setCloudBusy(true);
    try {
      const syncRes = await onRequestCloudSync?.({ restoreMissing: true });
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (syncRes && 'ok' in syncRes && !syncRes.ok) {
        setFeedback({
          type: 'err',
          text: syncRes.error || t('Bulut eşitlemesi başarısız oldu.', 'Cloud sync failed.'),
        });
      } else {
        const synced = syncRes && 'result' in syncRes ? syncRes.result : undefined;
        setFeedback({
          type: 'ok',
          text: synced
            ? t(
                `Bulut eşitlemesi tamamlandı: +${synced.restoredDatasets} depo / +${synced.restoredRecords} kayıt / +${synced.restoredUsers} üye geri yüklendi, +${synced.uploadedDatasets} depo yedeklendi.`,
                `Cloud sync finished: restored +${synced.restoredDatasets} datasets / +${synced.restoredRecords} records / +${synced.restoredUsers} users, uploaded +${synced.uploadedDatasets} datasets.`,
              )
            : t('Bulut eşitlemesi tamamlandı.', 'Cloud sync completed.'),
        });
      }
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Bulut eşitlemesi başarısız oldu.', 'Cloud sync failed.'),
      });
    } finally {
      setCloudBusy(false);
    }
  };

  const handleDownloadBackup = async () => {
    setFeedback(null);
    setVaultBusy(true);
    try {
      const snapshot = await apiAdminExportCloudSnapshot();
      const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentarika-vault-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      const omittedCount = snapshot.omittedLargeDatasets?.length || 0;
      const omittedNote =
        omittedCount > 0
          ? t(
              ` (${omittedCount} devasa disk deposu .json sınırını aştığı için hariç tutuldu; onları Depolar sekmesinden CSV/JSON indirebilirsiniz.)`,
              ` (${omittedCount} massive disk datasets exceeded single .json vault cap; export them individually in Datasets tab.)`,
            )
          : '';
      setFeedback({
        type: 'ok',
        text: t(
          `Tam sistem yedeği indirildi (${snapshot.datasets.length} depo, ${snapshot.records.length} kayıt, ${snapshot.users.length} üye).${omittedNote}`,
          `Full portable vault backup downloaded (${snapshot.datasets.length} datasets, ${snapshot.records.length} records, ${snapshot.users.length} members).${omittedNote}`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Yedek dosyası oluşturulamadı.', 'Failed to export backup.'),
      });
    } finally {
      setVaultBusy(false);
    }
  };

  const handleRestoreBackup = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setFeedback(null);
    setVaultBusy(true);
    try {
      const rawText = await file.text();
      const parsed = JSON.parse(rawText) as Partial<CloudBackupSnapshot> & { roles?: Partial<RoleConfigMap> };
      if (!parsed || typeof parsed !== 'object' || (!parsed.datasets && !parsed.records && !parsed.users && !parsed.roles)) {
        throw new Error(t('Geçersiz yedek JSON formatı.', 'Invalid vault backup JSON format.'));
      }
      const res = await apiAdminImportCloudSnapshot(parsed);
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({
        type: 'ok',
        text: t(
          `Yedekten geri yüklendi: +${res.restoredDatasets} depo, +${res.restoredRecords} kayıt, +${res.restoredUsers} üye.`,
          `Restored from vault: +${res.restoredDatasets} datasets, +${res.restoredRecords} records, +${res.restoredUsers} members.`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Yedek geri yüklenemedi.', 'Failed to restore backup.'),
      });
    } finally {
      setVaultBusy(false);
    }
  };

  const handleFilterDatabase = async (e?: FormEvent, nextDatasetId?: string) => {
    e?.preventDefault();
    setDbLoading(true);
    try {
      const targetDs = nextDatasetId !== undefined ? nextDatasetId : dbDatasetFilter;
      const res = await apiAdminDatabaseRecords(dbSearch.trim(), targetDs);
      setDbRecords(res.records);
      setDbTotal(res.total);
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Veritabanı kayıtları yüklenemedi.', 'Failed to load database records.') });
    } finally {
      setDbLoading(false);
    }
  };

  const handleExportData = async (
    format: 'csv' | 'json',
    opts: { datasetId?: string; q?: string } = {},
  ) => {
    setFeedback(null);
    setExportBusy(true);
    try {
      const { blob, filename, recordCount } = await apiAdminExportDataset({
        format,
        datasetId: opts.datasetId || undefined,
        q: opts.q?.trim() || undefined,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setFeedback({
        type: 'ok',
        text: t(
          `Veri dışa aktarıldı: ${filename} (${recordCount.toLocaleString('tr-TR')} kayıt).`,
          `Data exported: ${filename} (${recordCount.toLocaleString('en-US')} records).`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Veri dışa aktarılamadı.', 'Failed to export data.'),
      });
    } finally {
      setExportBusy(false);
    }
  };

  const handleAddBlacklist = async (e: FormEvent) => {
    e.preventDefault();
    if (!blacklistInput.trim()) return;
    setFeedback(null);
    setBlacklistBusy(true);
    try {
      const res = await apiAdminAddBlacklist(blacklistInput);
      setBlacklist(res.blacklist);
      setBlacklistInput('');
      const ignoredNote =
        res.ignored.length > 0
          ? t(` · Geçersiz atlanan: ${res.ignored.slice(0, 3).join(', ')}`, ` · Ignored invalid: ${res.ignored.slice(0, 3).join(', ')}`)
          : '';
      setFeedback({
        type: 'ok',
        text: t(
          `Kara listeye eklendi: ${res.addedIds} Discord ID, ${res.addedEmails} E-posta.${ignoredNote}`,
          `Added to blacklist: ${res.addedIds} Discord ID(s), ${res.addedEmails} Email(s).${ignoredNote}`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Kara listeye eklenemedi.', 'Failed to add blacklist entries.'),
      });
    } finally {
      setBlacklistBusy(false);
    }
  };

  const handleRemoveBlacklist = async (type: 'discord_id' | 'email', value: string) => {
    setFeedback(null);
    setBlacklistBusy(true);
    try {
      const res = await apiAdminRemoveBlacklist(type, value);
      setBlacklist(res.blacklist);
      setFeedback({
        type: 'ok',
        text: t(`Kara listeden kaldırıldı: ${value}`, `Removed from blacklist: ${value}`),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Kara listeden kaldırılamadı.', 'Failed to remove blacklist entry.'),
      });
    } finally {
      setBlacklistBusy(false);
    }
  };

  const handleToggleGlobalAdminBan = async (banned: boolean) => {
    setFeedback(null);
    setManagerBusy(true);
    try {
      const res = await apiManagerBanAdmin(banned, banned ? adminBanReasonInput : '');
      setAdminOversight(res.adminOversight);
      if (!banned) setAdminBanReasonInput('');
      setFeedback({
        type: 'ok',
        text: banned
          ? t('Admin hesabı yasaklandı ve aktif oturumu sonlandırıldı.', 'Admin account banned and active sessions revoked.')
          : t('Admin hesabı yasağı kaldırıldı.', 'Admin account ban lifted.'),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Admin durumu güncellenemedi.', 'Failed to update admin status.') });
    } finally {
      setManagerBusy(false);
    }
  };

  const handleToggleAdminIpBan = async (ip: string, banned: boolean) => {
    setFeedback(null);
    setManagerBusy(true);
    try {
      const res = await apiManagerBanAdminIp(ip, banned, banned ? t('Yönetici tarafından engellendi.', 'Banned by Manager.') : '');
      setAdminOversight(res.adminOversight);
      setFeedback({
        type: 'ok',
        text: banned
          ? t(`${ip} Admin IP adresi yasaklandı.`, `Admin IP ${ip} banned.`)
          : t(`${ip} Admin IP yasağı kaldırıldı.`, `Admin IP ${ip} unbanned.`),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('IP durumu güncellenemedi.', 'Failed to update IP status.') });
    } finally {
      setManagerBusy(false);
    }
  };

  const handleResetAdminKey = async (useCustom: boolean) => {
    setFeedback(null);
    setManagerBusy(true);
    setCopiedNewKey(false);
    try {
      const res = await apiManagerResetAdminKey(useCustom ? customAdminKeyInput.trim() : undefined);
      setAdminOversight(res.adminOversight);
      setGeneratedAdminKey(res.newAdminKey);
      if (useCustom) setCustomAdminKeyInput('');
      setFeedback({
        type: 'ok',
        text: t(
          'Admin anahtarı sıfırlandı ve yeni anahtar sisteme yüklendi. Eski Admin oturumları geçersiz kılındı.',
          'Admin key was reset and activated. Previous Admin sessions were invalidated.',
        ),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Admin anahtarı sıfırlanamadı.', 'Failed to reset Admin key.') });
    } finally {
      setManagerBusy(false);
    }
  };

  const handleCopyGeneratedAdminKey = async () => {
    if (!generatedAdminKey) return;
    try {
      await navigator.clipboard.writeText(generatedAdminKey);
      setCopiedNewKey(true);
      setTimeout(() => setCopiedNewKey(false), 2000);
    } catch {
      // Ignore clipboard failures
    }
  };

  if (!adminVerified) {
    return (
      <div className="flex h-40 items-center justify-center rounded-xl border border-slate-200 bg-white text-xs text-slate-500 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
        {t('Yönetici yetkisi sunucu tarafından doğrulanıyor...', 'Verifying administrator authorization with server...')}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <div>
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('Admin Yönetim Merkezi', 'Admin Control Center')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              'Kategorili veri depolarını yükleyin, kullanıcıların giriş/doğrulama bilgilerini ve tüm veritabanı kayıtlarını inceleyin.',
              'Upload categorized datasets, monitor user IP/verification details, and browse all database records.',
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setSubTab('datasets')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'datasets'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Database className="h-3.5 w-3.5" />
            <span>{t('Depolar', 'Datasets')} ({datasets.length})</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('users')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'users'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Users className="h-3.5 w-3.5" />
            <span>{t('Kullanıcılar', 'Users')} ({users.length})</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('database')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'database'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Table2 className="h-3.5 w-3.5" />
            <span>{t('Veritabanı', 'Database')}</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('roles')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'roles'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Sliders className="h-3.5 w-3.5" />
            <span>{t('Rol Hakları', 'Role Permissions')}</span>
          </button>
          <button
            type="button"
            data-testid="admin-tab-blacklist"
            onClick={() => setSubTab('blacklist')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'blacklist'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <ShieldOff className="h-3.5 w-3.5 text-rose-500" />
            <span>
              {t('Kara Liste', 'Blacklist')} ({blacklist.discordIds.length + blacklist.emails.length})
            </span>
          </button>
          {isRootManager && adminOversight && (
            <button
              type="button"
              data-testid="admin-tab-manager"
              onClick={() => setSubTab('manager')}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                subTab === 'manager'
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5 text-amber-500" />
              <span>{t('Yönetici Denetimi', 'Manager Control')}</span>
            </button>
          )}
        </div>
      </section>

      {feedback && (
        <div
          role="status"
          className={`flex items-center gap-2 rounded-lg border p-3 text-xs ${
            feedback.type === 'ok'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300'
              : 'border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300'
          }`}
        >
          {feedback.type === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <AlertCircle className="h-4 w-4 shrink-0" />}
          <span>{feedback.text}</span>
        </div>
      )}

      {loading ? (
        <div className="h-40 animate-pulse rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]" />
      ) : (
        <>
          {subTab === 'datasets' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2.5">
                {datasets.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
                      {t('Veri Dışa Aktar:', 'Export Data:')}
                    </span>
                    <button
                      type="button"
                      data-testid="export-all-csv-btn"
                      disabled={exportBusy}
                      onClick={() => handleExportData('csv')}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-300/80 bg-emerald-50/70 px-3 py-1.5 text-xs font-semibold text-emerald-700 hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-800/80 dark:bg-emerald-950/30 dark:text-emerald-300 dark:hover:bg-emerald-950/50 whitespace-nowrap"
                    >
                      <FileSpreadsheet className="h-3.5 w-3.5" />
                      <span>{t('Tümünü CSV İndir', 'Export All CSV')}</span>
                    </button>
                    <button
                      type="button"
                      data-testid="export-all-json-btn"
                      disabled={exportBusy}
                      onClick={() => handleExportData('json')}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                    >
                      <FileJson className="h-3.5 w-3.5" />
                      <span>{t('Tümünü JSON İndir', 'Export All JSON')}</span>
                    </button>
                  </div>
                ) : (
                  <div />
                )}

                <div className="flex flex-wrap items-center justify-end gap-2.5">
                  <button
                    type="button"
                    onClick={handleLoadSynthetic}
                    className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                  >
                    {t('Sentetik Test Verisi Yükle', 'Load Synthetic Test Data')}
                  </button>
                  <button
                    type="button"
                    onClick={onOpenImport}
                    className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700"
                  >
                    <Upload className="h-3.5 w-3.5" />
                    <span>{t('Yeni Veri Deposu Yükle', 'Upload New Dataset')}</span>
                  </button>
                </div>
              </div>

              {datasets.length === 0 ? (
                <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  {t('Henüz sunucuda yüklü veri deposu yok.', 'No datasets uploaded to the server yet.')}
                </div>
              ) : (
                <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-semibold">{t('Depo Adı', 'Dataset Name')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Kapsam', 'Indexing')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Biçim', 'Format')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Kayıt', 'Records')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Eklenme Tarihi', 'Added At')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('İşlem', 'Action')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {datasets.map((ds) => (
                          <tr key={ds.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-3 font-semibold text-slate-900 dark:text-slate-100">{ds.name}</td>
                            <td className="px-4 py-3 font-medium">
                              {ds.ingestionStatus === 'uploading' ? (
                                <span className="text-amber-600 dark:text-amber-400">
                                  {t('Ham Dosya Aktarılıyor...', 'Uploading Raw File...')}
                                </span>
                              ) : ds.ingestionStatus === 'analyzing' ? (
                                <span className="text-blue-600 dark:text-blue-400">
                                  {t('Arka Planda Analiz Ediliyor...', 'Analyzing in Background...')}
                                </span>
                              ) : ds.ingestionStatus === 'error' ? (
                                <span className="text-red-600 dark:text-red-400" title={ds.ingestionError || ''}>
                                  {t('Analiz Hatası', 'Analysis Error')}
                                </span>
                              ) : (
                                <span className="text-emerald-600 dark:text-emerald-400">
                                  {ds.storageMode === 'disk'
                                    ? t('Otomatik · Disk İndeks (Tüm Sorgular)', 'Automatic · Disk Index (All Queries)')
                                    : t('Otomatik (Tüm Sorgular)', 'Automatic (All Queries)')}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono uppercase text-slate-600 dark:text-slate-300">{ds.format}</td>
                            <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-800 dark:text-slate-200">
                              {ds.recordCount.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}
                            </td>
                            <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(ds.importedAt)}
                            </td>
                            <td className="px-4 py-3 text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1.5">
                                <button
                                  type="button"
                                  data-testid={`export-ds-csv-${ds.id}`}
                                  disabled={exportBusy}
                                  onClick={() => handleExportData('csv', { datasetId: ds.id })}
                                  aria-label={`${t('Veri Dışa Aktar (.csv)', 'Export CSV')}: ${ds.name}`}
                                  title={t('CSV olarak dışa aktar', 'Export as CSV')}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-50 disabled:opacity-50 dark:border-slate-700 dark:text-emerald-400 dark:hover:bg-emerald-950/40"
                                >
                                  <Download className="h-3 w-3" />
                                  <span>CSV</span>
                                </button>
                                <button
                                  type="button"
                                  data-testid={`export-ds-json-${ds.id}`}
                                  disabled={exportBusy}
                                  onClick={() => handleExportData('json', { datasetId: ds.id })}
                                  aria-label={`${t('Veri Dışa Aktar (.json)', 'Export JSON')}: ${ds.name}`}
                                  title={t('JSON olarak dışa aktar', 'Export as JSON')}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                                >
                                  <Download className="h-3 w-3" />
                                  <span>JSON</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setEditingDataset(ds)}
                                  aria-label={`${t('Düzenle', 'Edit')}: ${ds.name}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-blue-600 hover:bg-blue-50 dark:border-slate-700 dark:text-blue-400 dark:hover:bg-blue-950/40"
                                >
                                  <Pencil className="h-3 w-3" />
                                  <span>{t('Düzenle', 'Edit')}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteDataset(ds.id)}
                                  aria-label={`${t('Sil', 'Delete')}: ${ds.name}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-slate-700 dark:text-red-400 dark:hover:bg-red-950/40"
                                >
                                  <Trash2 className="h-3 w-3" />
                                  <span>{t('Sil', 'Delete')}</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {subTab === 'users' && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-5 py-3.5 dark:border-slate-800 dark:bg-[#111827]">
                <div className="text-xs text-slate-600 dark:text-slate-400">
                  {t(
                    'Tüm üye oturumlarını sonlandırabilir veya üye hesaplarını temizleyip yalnızca Admin hesabını bırakabilirsiniz.',
                    'Terminate all active member sessions or clear member accounts so only Admin remains.',
                  )}
                </div>
                {kickConfirmOpen ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleKickAllUsers(false)}
                      className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-800 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300"
                    >
                      {t('Sadece Oturumları At', 'Kick Active Sessions')}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleKickAllUsers(true)}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-700"
                    >
                      {t('Üyeleri Sil ve At', 'Delete & Kick All')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setKickConfirmOpen(false)}
                      className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                    >
                      {t('İptal', 'Cancel')}
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    data-testid="kick-all-users-btn"
                    onClick={() => setKickConfirmOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-1.5 text-xs font-semibold text-red-700 hover:bg-red-100 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50"
                  >
                    <UserX className="h-3.5 w-3.5" />
                    <span>{t('Tüm Kullanıcıları At', 'Kick All Users')}</span>
                  </button>
                )}
              </div>

              <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                {users.length === 0 ? (
                  <div className="p-10 text-center text-sm text-slate-500 dark:text-slate-400">
                    {t('Henüz kayıtlı üye bulunmuyor.', 'No registered members yet.')}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-semibold">{t('Kullanıcı / Profil', 'User / Profile')}</th>
                          <th className="px-4 py-3 font-semibold">{t('E-posta & Doğrulama', 'Email & Verification')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Son Giriş Bilgisi', 'Last Login Info')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Rol', 'Role')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Kota', 'Quota')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Durum', 'Status')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Yönetim', 'Manage')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {users.map((u) => (
                          <tr key={u.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-3 align-top">
                              <div className="font-semibold text-slate-900 dark:text-slate-100">
                                {u.displayName || u.username}
                              </div>
                              <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                                @{u.username}
                              </div>
                            </td>
                            <td className="px-4 py-3 align-top">
                              <div className="font-mono text-slate-700 dark:text-slate-200">{u.email}</div>
                              {u.emailVerified ? (
                                <div className="mt-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                                  {u.authProvider === 'google'
                                    ? t('Google Hesabı (Doğrulandı)', 'Google Account (Verified)')
                                    : t('E-posta Doğrulandı', 'Email Verified')}
                                </div>
                              ) : (
                                <div className="mt-1 flex flex-wrap items-center gap-2">
                                  <span className="font-mono text-[11px] text-amber-600 dark:text-amber-400">
                                    {t('Onay Bekliyor', 'Pending')}
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() => handleApproveEmail(u.id)}
                                    className="inline-flex items-center gap-1 rounded border border-emerald-300 bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 hover:bg-emerald-100 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                                  >
                                    <MailCheck className="h-3 w-3" />
                                    <span>{t('Onayla', 'Approve')}</span>
                                  </button>
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 align-top font-mono text-[11px] text-slate-600 dark:text-slate-400">
                              <div>IP: {u.lastLoginIp || '—'}</div>
                              <div>{u.lastLoginAt ? formatTurkishDate(u.lastLoginAt) : t('Henüz giriş yok', 'No login yet')}</div>
                            </td>
                            <td className="px-4 py-3 align-top">
                              <select
                                aria-label={`${u.username} ${t('rolü', 'role')}`}
                                value={u.role}
                                onChange={(e) => handleChangeUserRole(u.id, e.target.value as StandardRole)}
                                className="rounded-md border border-slate-300 bg-slate-50 px-2 py-1 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                              >
                                {STANDARD_ROLES.map((r) => (
                                  <option key={r} value={r}>
                                    {r}
                                  </option>
                                ))}
                              </select>
                            </td>
                            <td className="px-4 py-3 align-top text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                              {u.dailyUsed} / {u.permissions.dailyQueryLimit}
                            </td>
                            <td className="px-4 py-3 align-top">
                              {u.banned ? (
                                <span className="font-medium text-red-600 dark:text-red-400">
                                  {t('Yasaklı', 'Banned')} ({u.banReason || 'Ban'})
                                </span>
                              ) : (
                                <span className="font-medium text-emerald-700 dark:text-emerald-400">{t('Aktif', 'Active')}</span>
                              )}
                            </td>
                            <td className="px-4 py-3 align-top text-right whitespace-nowrap">
                              {u.banned ? (
                                <button
                                  type="button"
                                  onClick={() => handleConfirmBan(u.id, false)}
                                  className="rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-50 dark:border-slate-700 dark:text-emerald-400 dark:hover:bg-emerald-950/30"
                                >
                                  {t('Yasağı Kaldır', 'Unban')}
                                </button>
                              ) : banTargetId === u.id ? (
                                <div className="inline-flex items-center gap-1.5">
                                  <input
                                    type="text"
                                    value={banReason}
                                    onChange={(e) => setBanReason(e.target.value)}
                                    placeholder={t('Ban sebebi', 'Ban reason')}
                                    className="w-32 rounded border border-slate-300 bg-slate-50 px-2 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                  />
                                  <button
                                    type="button"
                                    onClick={() => handleConfirmBan(u.id, true)}
                                    className="rounded bg-red-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-red-700"
                                  >
                                    {t('Onayla', 'Confirm')}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setBanTargetId(null);
                                      setBanReason('');
                                    }}
                                    className="rounded border border-slate-300 px-2 py-1 text-[11px] dark:border-slate-700"
                                  >
                                    {t('İptal', 'Cancel')}
                                  </button>
                                </div>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setBanTargetId(u.id)}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-slate-700 dark:text-red-400 dark:hover:bg-red-950/40"
                                >
                                  <Ban className="h-3 w-3" />
                                  <span>{t('Yasakla', 'Ban')}</span>
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <section className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                <div className="border-b border-slate-200 px-5 py-4 dark:border-slate-800">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-500" />
                    <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t('Engellenen Temp-Mail / Kayıt Denemeleri', 'Blocked Temp-Mail / Registration Attempts')} ({blockedAttempts.length})
                    </h3>
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    {t(
                      'Tek kullanımlık (disposable) e-posta veya geçersiz MX kaydı nedeniyle reddedilen tüm kayıt girişimleri IP adresleriyle birlikte kaydedilir.',
                      'All registration attempts rejected due to disposable email domains or invalid MX records, logged with IP addresses.',
                    )}
                  </p>
                </div>

                {blockedAttempts.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    {t('Henüz engellenmiş temp-mail veya geçersiz kayıt denemesi yok.', 'No blocked temp-mail or invalid registration attempts yet.')}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-2.5 font-semibold">{t('Denenen E-posta', 'Attempted Email')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Kullanıcı Adı', 'Username')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Alan Adı', 'Domain')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Tespit Katmanı & Sebep', 'Detector & Reason')}</th>
                          <th className="px-4 py-2.5 font-semibold">IP</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Zaman', 'Time')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {blockedAttempts.map((b) => (
                          <tr key={b.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-2.5 font-mono text-red-600 dark:text-red-400">{b.email}</td>
                            <td className="px-4 py-2.5 font-mono text-slate-800 dark:text-slate-200">@{b.username}</td>
                            <td className="px-4 py-2.5 font-mono text-slate-700 dark:text-slate-300">{b.domain}</td>
                            <td className="px-4 py-2.5 text-slate-700 dark:text-slate-300">
                              <span className="mr-1.5 font-mono text-[11px] font-semibold uppercase text-amber-600 dark:text-amber-400">
                                [{b.detector}]
                              </span>
                              <span>{b.reason}</span>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[11px] text-slate-600 dark:text-slate-400">{b.ip}</td>
                            <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(b.timestamp)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}

          {subTab === 'database' && (
            <div className="space-y-6">
              <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t('Veritabanı Kayıt Gezgini', 'Database Record Explorer')} ({dbTotal.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} {t('kayıt', 'records')})
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {t(
                        'Tüm veri depolarındaki ham kayıtları ID, e-posta, kullanıcı adı veya not alanına göre filtreleyin.',
                        'Filter raw records across all datasets by ID, email, username, or notes.',
                      )}
                    </p>
                  </div>
                  <form onSubmit={(e) => handleFilterDatabase(e)} className="flex flex-wrap items-center gap-2">
                    <select
                      aria-label={t('Depo filtresi', 'Dataset filter')}
                      value={dbDatasetFilter}
                      onChange={(e) => {
                        setDbDatasetFilter(e.target.value);
                        void handleFilterDatabase(undefined, e.target.value);
                      }}
                      className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                    >
                      <option value="">{t('Tüm Depolar', 'All Datasets')}</option>
                      {datasets.map((ds) => (
                        <option key={ds.id} value={ds.id}>
                          {ds.name}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={dbSearch}
                      onChange={(e) => setDbSearch(e.target.value)}
                      placeholder={t('Kayıt içinde ara...', 'Search records...')}
                      className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="submit"
                      disabled={dbLoading}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      <Search className="h-3.5 w-3.5" />
                      <span>{t('Filtrele', 'Filter')}</span>
                    </button>
                    <button
                      type="button"
                      data-testid="export-db-csv-btn"
                      disabled={exportBusy || dbTotal === 0}
                      onClick={() => handleExportData('csv', { datasetId: dbDatasetFilter, q: dbSearch })}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-300/80 bg-emerald-50/70 px-3 py-1.5 text-xs font-semibold text-emerald-700 hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-800/80 dark:bg-emerald-950/30 dark:text-emerald-300 dark:hover:bg-emerald-950/50 whitespace-nowrap"
                    >
                      <FileSpreadsheet className="h-3.5 w-3.5" />
                      <span>{t('Veri Dışa Aktar (.csv)', 'Export Data (.csv)')}</span>
                    </button>
                    <button
                      type="button"
                      data-testid="export-db-json-btn"
                      disabled={exportBusy || dbTotal === 0}
                      onClick={() => handleExportData('json', { datasetId: dbDatasetFilter, q: dbSearch })}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                    >
                      <FileJson className="h-3.5 w-3.5" />
                      <span>{t('Veri Dışa Aktar (.json)', 'Export Data (.json)')}</span>
                    </button>
                  </form>
                </div>

                <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  {dbRecords.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                      {t('Eşleşen veritabanı kaydı bulunamadı.', 'No matching database records found.')}
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-3 py-2.5 font-semibold">Discord ID</th>
                          <th className="px-3 py-2.5 font-semibold">{t('E-posta', 'Email')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Kullanıcı Adı', 'Username')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Kaynak / Depo', 'Source / Dataset')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('IP / Ek', 'IP / Extra')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {dbRecords.slice(0, 100).map((r) => (
                          <tr key={r.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-3 py-2 font-mono text-blue-600 dark:text-blue-400">{r.discordId || '—'}</td>
                            <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">{r.email || '—'}</td>
                            <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{r.username || '—'}</td>
                            <td className="px-3 py-2 text-slate-600 dark:text-slate-400">
                              {r.source} <span className="text-[11px] opacity-75">({r.datasetName})</span>
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {r.ip || r.notes || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {t('Son Sorgu Denetim Kayıtları', 'Recent Query Audit Logs')} ({queryLogs.length})
                </h3>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {t(
                    'Kullanıcıların panelde gerçekleştirdiği son ID Lookup, E-posta OSINT ve Toplu Sorgu işlemleri.',
                    'Recent ID Lookup, Email OSINT, and Bulk Lookup operations executed by panel users.',
                  )}
                </p>

                <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  {queryLogs.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                      {t('Henüz sorgu denetim kaydı oluşmadı.', 'No query audit logs yet.')}
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-3 py-2.5 font-semibold">{t('Kullanıcı', 'User')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Modül', 'Module')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Hedef', 'Target')}</th>
                          <th className="px-3 py-2.5 text-right font-semibold">{t('Sonuç', 'Matches')}</th>
                          <th className="px-3 py-2.5 font-semibold">IP</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Zaman', 'Time')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {queryLogs.slice(0, 60).map((log) => (
                          <tr key={log.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-3 py-2 font-semibold text-slate-900 dark:text-slate-100">{log.username}</td>
                            <td className="px-3 py-2 text-slate-700 dark:text-slate-300">
                              {queryTypeLabel(log.queryType)}
                            </td>
                            <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">{log.target}</td>
                            <td className="px-3 py-2 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                              {log.matchCount}
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {log.ip}
                            </td>
                            <td className="px-3 py-2 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(log.timestamp)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>
            </div>
          )}

          {subTab === 'roles' && roles && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {STANDARD_ROLES.map((roleName) => {
                const cfg = roles[roleName];
                return (
                  <div
                    key={roleName}
                    className="flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]"
                  >
                    <div className="space-y-4">
                      <div className="border-b border-slate-200 pb-3 dark:border-slate-800">
                        <h3 className="font-display text-base font-bold text-slate-900 dark:text-slate-100">
                          {roleName} {t('Rolü', 'Role')}
                        </h3>
                        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                          {roleName === 'Üye'
                            ? t('Yeni kayıt olan standart kullanıcılar', 'Standard newly registered users')
                            : roleName === 'Destekçi'
                              ? t('Gelişmiş özelliklere erişen destekçiler', 'Supporters with extended features')
                              : t('Yüksek kotalı kurumsal/işletme hesapları', 'High-quota business accounts')}
                        </p>
                      </div>

                      <div>
                        <label
                          htmlFor={`quota-${roleName}`}
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                        >
                          {t('Günlük Sorgu Hakkı', 'Daily Query Quota')}
                        </label>
                        <input
                          id={`quota-${roleName}`}
                          type="number"
                          min={0}
                          max={1000000}
                          value={cfg.dailyQueryLimit}
                          onChange={(e) =>
                            handleRoleFieldChange(roleName, 'dailyQueryLimit', Math.max(0, Number(e.target.value) || 0))
                          }
                          className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-sm text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                        />
                      </div>

                      <div className="space-y-2.5 text-xs">
                        {(
                          [
                            ['canIdLookup', t('Discord ID Sorgulama', 'Discord ID Lookup')],
                            ['canEmailOsint', t('E-posta OSINT Modülü', 'Email OSINT Module')],
                            ['canBulkLookup', t('Toplu ID Tarama', 'Bulk ID Lookup')],
                          ] as [keyof RolePermissions, string][]
                        ).map(([permKey, label]) => (
                          <label key={permKey} className="flex cursor-pointer items-center justify-between gap-2">
                            <span className="text-slate-700 dark:text-slate-300">{label}</span>
                            <input
                              type="checkbox"
                              checked={Boolean(cfg[permKey])}
                              onChange={(e) => handleRoleFieldChange(roleName, permKey, e.target.checked)}
                              className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 dark:border-slate-600 dark:bg-slate-800"
                            />
                          </label>
                        ))}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveRole(roleName)}
                      className="mt-5 w-full rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-blue-700"
                    >
                      {roleName} {t('Haklarını Kaydet', 'Save Permissions')} ({lang.toUpperCase()})
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          {subTab === 'blacklist' && (
            <div className="space-y-6">
              <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
                <div className="flex items-start gap-3">
                  <ShieldOff className="mt-0.5 h-5 w-5 shrink-0 text-rose-500" />
                  <div>
                    <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t('Sorgu Kara Listesi (Discord ID & E-posta)', 'Query Blacklist (Discord ID & Email)')}
                    </h3>
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                      {t(
                        'Buraya yazılan Discord ID ve e-posta adresleri veri depolarından silinmez; ancak ID Sorgu, Toplu Sorgu, E-posta OSINT ve Snowflake üzerinden asla sorgulanamaz. Kullanıcılar "kara listede, sorgulanamaz" uyarısı görür.',
                        'Discord IDs and emails added here remain in datasets but can never be queried in ID Lookup, Bulk Lookup, Email OSINT, or Snowflake. Users see a blacklist blocked notice.',
                      )}
                    </p>
                  </div>
                </div>

                <form onSubmit={handleAddBlacklist} className="mt-4 space-y-3">
                  <label htmlFor="blacklist-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    {t(
                      'Discord ID veya E-posta Adresleri (alt alta, virgül veya boşlukla ayırın — otomatik tanınır)',
                      'Discord IDs or Email Addresses (separate by newline, comma, or space — auto-detected)',
                    )}
                  </label>
                  <textarea
                    id="blacklist-input"
                    data-testid="blacklist-input"
                    rows={4}
                    value={blacklistInput}
                    onChange={(e) => setBlacklistInput(e.target.value)}
                    placeholder={'104567890123456789\nkorunan@ornek.com'}
                    className="w-full rounded-lg border border-slate-300 bg-slate-50 p-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-rose-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <button
                      type="submit"
                      data-testid="blacklist-add-btn"
                      disabled={blacklistBusy || !blacklistInput.trim()}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-rose-700 disabled:opacity-50"
                    >
                      <Ban className="h-3.5 w-3.5" />
                      <span>{blacklistBusy ? t('Kaydediliyor...', 'Saving...') : t('Kara Listeye Ekle', 'Add to Blacklist')}</span>
                    </button>
                  </div>
                </form>
              </div>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                  <h4 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    {t('Kara Listedeki Discord ID’ler', 'Blacklisted Discord IDs')} ({blacklist.discordIds.length})
                  </h4>
                  {blacklist.discordIds.length === 0 ? (
                    <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                      {t('Henüz kara listeye eklenmiş Discord ID yok.', 'No blacklisted Discord IDs yet.')}
                    </p>
                  ) : (
                    <ul className="mt-3 max-h-80 space-y-1.5 overflow-y-auto pr-1">
                      {blacklist.discordIds.map((id) => (
                        <li
                          key={id}
                          className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-200"
                        >
                          <span className="truncate">{id}</span>
                          <button
                            type="button"
                            disabled={blacklistBusy}
                            onClick={() => handleRemoveBlacklist('discord_id', id)}
                            aria-label={t(`${id} kaydını kaldır`, `Remove ${id}`)}
                            className="inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-[11px] font-sans font-medium text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/40"
                          >
                            <X className="h-3.5 w-3.5" />
                            <span>{t('Kaldır', 'Remove')}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                  <h4 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    {t('Kara Listedeki E-postalar', 'Blacklisted Emails')} ({blacklist.emails.length})
                  </h4>
                  {blacklist.emails.length === 0 ? (
                    <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                      {t('Henüz kara listeye eklenmiş e-posta yok.', 'No blacklisted emails yet.')}
                    </p>
                  ) : (
                    <ul className="mt-3 max-h-80 space-y-1.5 overflow-y-auto pr-1">
                      {blacklist.emails.map((email) => (
                        <li
                          key={email}
                          className="flex items-center justify-between gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-200"
                        >
                          <span className="truncate">{email}</span>
                          <button
                            type="button"
                            disabled={blacklistBusy}
                            onClick={() => handleRemoveBlacklist('email', email)}
                            aria-label={t(`${email} kaydını kaldır`, `Remove ${email}`)}
                            className="inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-[11px] font-sans font-medium text-rose-600 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/40"
                          >
                            <X className="h-3.5 w-3.5" />
                            <span>{t('Kaldır', 'Remove')}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}

          {subTab === 'manager' && isRootManager && adminOversight && (
            <div className="space-y-6" data-testid="manager-oversight-panel">
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <section
                  data-testid="manager-cloud-sync-card"
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {t('Yönetici Bulut Eşitleme ve Veri Geri Yükleme', 'Manager Cloud Sync & Recovery')}
                      </h3>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        {t(
                          'Yetkili Yönetici Google hesabınızı bağladığınızda tüm üyeler, rol yetkileri ve 12.500 kayıt altındaki veri depoları Firebase Firestore’a yedeklenir ve sunucu yeniden başlasa dahi geri yüklenir.',
                          'Link an authorized Manager Google account to sync members, role permissions, and datasets under 12,500 records to Firestore and restore across restarts.',
                        )}
                      </p>
                    </div>
                    <Cloud className="h-5 w-5 shrink-0 text-blue-500" />
                  </div>

                  <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
                    {isCloudRootAdminConnected() || cloudConnected ? (
                      <span className="inline-flex items-center gap-1.5 rounded border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 font-semibold text-emerald-700 dark:text-emerald-400">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span>
                          {t('Hesap Bağlı:', 'Connected:')}{' '}
                          {getConnectedCloudAdminEmail() || t('Yetkili Yönetici', 'Authorized Manager')}
                        </span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded border border-slate-300 bg-slate-100 px-2.5 py-1 font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                        <span>{t('Google hesabı bağlı değil', 'Google account not connected')}</span>
                      </span>
                    )}
                    {cloudSyncStatus === 'syncing' && (
                      <span className="font-medium text-blue-600 dark:text-blue-400">
                        {t('Eşitleniyor...', 'Syncing...')}
                      </span>
                    )}
                  </div>

                  {cloudSyncError ? (
                    <div className="mt-3 rounded-lg border border-red-200 bg-red-50/80 p-3 text-xs text-red-800 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
                      {cloudSyncError}
                    </div>
                  ) : cloudSyncDetail ? (
                    <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-300">
                      {cloudSyncDetail}
                    </div>
                  ) : null}

                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    {isCloudRootAdminConnected() || cloudConnected ? (
                      <>
                        <button
                          type="button"
                          data-testid="firestore-manual-sync-btn"
                          disabled={cloudBusy || cloudSyncStatus === 'syncing'}
                          onClick={handleManualCloudSync}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                        >
                          <RefreshCw className="h-3.5 w-3.5" />
                          <span>{t('Bulut ile Eşitle ve Verileri Geri Yükle', 'Sync & Restore from Cloud')}</span>
                        </button>
                        <button
                          type="button"
                          data-testid="firestore-connect-btn"
                          disabled={cloudBusy}
                          onClick={handleConnectCloudAdmin}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                        >
                          <Cloud className="h-3.5 w-3.5" />
                          <span>{t('Hesap Değiştir', 'Switch Account')}</span>
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        data-testid="firestore-connect-btn"
                        disabled={cloudBusy}
                        onClick={handleConnectCloudAdmin}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                      >
                        <Cloud className="h-3.5 w-3.5" />
                        <span>{t('Google Hesabı Bağla ve Bulutla Eşitle', 'Connect Google & Sync Cloud')}</span>
                      </button>
                    )}
                  </div>
                </section>

                <section
                  data-testid="manager-vault-card"
                  className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {t('Yönetici Tam Yedek Kasası (.json)', 'Manager Full Vault Backup (.json)')}
                      </h3>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        {t(
                          'Yalnızca Yönetici anahtarına özeldir. Tüm uygun disk/bellek veri depolarını, kayıtlı üyeleri, rol yetkilerini ve kara listeyi tek .json dosyası olarak indirip istediğiniz zaman geri yükleyin.',
                          'Exclusive to the Manager Key. Download or restore datasets, members, role permissions, and the blacklist as a single portable .json vault.',
                        )}
                      </p>
                    </div>
                    <Download className="h-5 w-5 shrink-0 text-emerald-500" />
                  </div>

                  <div className="mt-5 flex flex-wrap items-center gap-2.5">
                    <input
                      ref={restoreInputRef}
                      type="file"
                      accept=".json,application/json"
                      onChange={handleRestoreBackup}
                      className="hidden"
                    />
                    <button
                      type="button"
                      data-testid="download-vault-btn"
                      disabled={vaultBusy}
                      onClick={handleDownloadBackup}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                    >
                      <Download className="h-3.5 w-3.5" />
                      <span>{vaultBusy ? t('Hazırlanıyor...', 'Preparing...') : t('Tam Yedek İndir (.json)', 'Download Full Vault (.json)')}</span>
                    </button>
                    <button
                      type="button"
                      data-testid="restore-vault-btn"
                      disabled={vaultBusy}
                      onClick={() => restoreInputRef.current?.click()}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                    >
                      <FileUp className="h-3.5 w-3.5" />
                      <span>{t('Yedekten Geri Yükle', 'Restore Vault')}</span>
                    </button>
                  </div>
                </section>
              </div>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {t('Admin Hesabı Erişim & Yasaklama Kontrolü', 'Admin Account Access & Ban Control')}
                      </h3>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        {t(
                          'Standart Admin anahtarıyla giriş yapan tüm Admin erişimini tek tıkla yasaklayabilir veya tekrar açabilirsiniz. Yasaklandığında aktif Admin oturumları anında sonlanır.',
                          'Ban or restore the Admin tier globally with a single click. Banning immediately revokes active Admin tokens.',
                        )}
                      </p>
                    </div>
                    <span
                      className={`shrink-0 rounded border px-2.5 py-1 text-[11px] font-semibold ${
                        adminOversight.adminBanned
                          ? 'border-red-300 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300'
                          : 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300'
                      }`}
                    >
                      {adminOversight.adminBanned ? t('Admin Yasaklı', 'Admin Banned') : t('Admin Aktif', 'Admin Active')}
                    </span>
                  </div>

                  {adminOversight.adminBanned ? (
                    <div className="mt-4 space-y-3 rounded-lg border border-red-200 bg-red-50/70 p-4 text-xs text-red-900 dark:border-red-900/50 dark:bg-red-950/25 dark:text-red-200">
                      <div>
                        <span className="font-semibold">{t('Yasak Nedeni:', 'Ban Reason:')}</span>{' '}
                        {adminOversight.adminBanReason || '—'}
                      </div>
                      <button
                        type="button"
                        disabled={managerBusy}
                        onClick={() => handleToggleGlobalAdminBan(false)}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span>{t('Admin Yasağını Kaldır', 'Unban Admin Account')}</span>
                      </button>
                    </div>
                  ) : (
                    <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                      <input
                        type="text"
                        value={adminBanReasonInput}
                        onChange={(e) => setAdminBanReasonInput(e.target.value)}
                        placeholder={t('Yasaklama nedeni (opsiyonel)...', 'Ban reason (optional)...')}
                        className="flex-1 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 text-xs text-slate-900 focus:border-red-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                      />
                      <button
                        type="button"
                        data-testid="manager-ban-admin-btn"
                        disabled={managerBusy}
                        onClick={() => handleToggleGlobalAdminBan(true)}
                        className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-700 disabled:opacity-50 whitespace-nowrap"
                      >
                        <Ban className="h-3.5 w-3.5" />
                        <span>{t('Admin Hesabını Yasakla', 'Ban Admin Account')}</span>
                      </button>
                    </div>
                  )}
                </section>

                <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                        {t('Admin Anahtarı Sıfırlama & Oto Yükleme', 'Admin Key Reset & Auto-Rotation')}
                      </h3>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                        {t(
                          'Yeni 30 haneli CSPRNG Admin anahtarını otomatik üretip sisteme yükleyin veya kendi 30 haneli anahtarınızı tanımlayın.',
                          'Auto-generate and activate a fresh 30-digit CSPRNG Admin key, or assign your own custom 30-digit key.',
                        )}
                      </p>
                    </div>
                    <KeyRound className="h-5 w-5 shrink-0 text-amber-500" />
                  </div>

                  {adminOversight.adminKeyUpdatedAt && (
                    <div className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">
                      {t('Son Anahtar Değişikliği:', 'Last Key Rotation:')} {formatTurkishDate(adminOversight.adminKeyUpdatedAt)}
                    </div>
                  )}

                  <div className="mt-4 space-y-3">
                    <button
                      type="button"
                      data-testid="manager-auto-reset-key-btn"
                      disabled={managerBusy}
                      onClick={() => handleResetAdminKey(false)}
                      className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-amber-600 px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-amber-700 disabled:opacity-50"
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      <span>{t('Oto Yeni 30 Haneli Admin Key Oluştur ve Yükle', 'Auto-Generate & Load New 30-Digit Admin Key')}</span>
                    </button>

                    <div className="flex flex-col gap-2 sm:flex-row">
                      <input
                        type="text"
                        inputMode="numeric"
                        maxLength={30}
                        value={customAdminKeyInput}
                        onChange={(e) => setCustomAdminKeyInput(e.target.value.replace(/\D/g, '').slice(0, 30))}
                        placeholder={t('Veya özel 30 haneli sayısal key girin...', 'Or enter custom 30-digit numeric key...')}
                        className="flex-1 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-900 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                      />
                      <button
                        type="button"
                        disabled={managerBusy || customAdminKeyInput.length !== 30}
                        onClick={() => handleResetAdminKey(true)}
                        className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                      >
                        {t('Özel Key Yükle', 'Apply Custom Key')} ({customAdminKeyInput.length}/30)
                      </button>
                    </div>

                    {generatedAdminKey && (
                      <div
                        data-testid="manager-new-admin-key-box"
                        className="rounded-lg border border-emerald-300 bg-emerald-50 p-3 text-xs text-emerald-950 dark:border-emerald-800 dark:bg-emerald-950/35 dark:text-emerald-200"
                      >
                        <div className="flex items-center justify-between gap-2 font-semibold">
                          <span>{t('Aktif Yeni Admin Anahtarı (Hemen Kopyalayın):', 'New Active Admin Key (Copy Now):')}</span>
                          <button
                            type="button"
                            onClick={handleCopyGeneratedAdminKey}
                            className="inline-flex items-center gap-1 rounded border border-emerald-400/60 bg-white/80 px-2 py-0.5 text-[11px] font-semibold text-emerald-800 hover:bg-white dark:border-emerald-700 dark:bg-slate-900 dark:text-emerald-300"
                          >
                            <Copy className="h-3 w-3" />
                            <span>{copiedNewKey ? t('Kopyalandı', 'Copied') : t('Kopyala', 'Copy')}</span>
                          </button>
                        </div>
                        <div className="mt-1.5 select-all break-all font-mono text-sm font-bold tracking-wider">
                          {generatedAdminKey}
                        </div>
                      </div>
                    )}
                  </div>
                </section>
              </div>

              <section className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                <div className="border-b border-slate-200 px-5 py-4 dark:border-slate-800">
                  <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {t('Admin Giriş ve İşlem IP Kayıtları', 'Tracked Admin Login & Activity IPs')} ({adminOversight.trackedIps.length})
                  </h3>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    {t(
                      'Standart Admin hesabının giriş yaptığı ve sorgu çalıştırdığı IP adresleri yalnızca Yönetici panelinde görünür. İstediğiniz Admin IP adresini buradan banlayabilirsiniz.',
                      'IP addresses used by standard Admin sessions appear exclusively here in the Manager panel. You can ban or unban any Admin IP immediately.',
                    )}
                  </p>
                </div>

                {adminOversight.trackedIps.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    {t('Henüz kaydedilmiş Admin IP adresi yok.', 'No Admin IP addresses recorded yet.')}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Admin IP</th>
                          <th className="px-4 py-3 font-semibold">{t('İlk Görülme', 'First Seen')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Son İşlem', 'Last Seen')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Giriş', 'Logins')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Sorgu', 'Queries')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Durum', 'Status')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('İşlem', 'Action')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {adminOversight.trackedIps.map((row) => (
                          <tr key={row.ip} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-3 font-mono font-semibold text-slate-900 dark:text-slate-100">{row.ip}</td>
                            <td className="px-4 py-3 text-slate-500 dark:text-slate-400">{formatTurkishDate(row.firstSeenAt)}</td>
                            <td className="px-4 py-3 text-slate-600 dark:text-slate-300">{formatTurkishDate(row.lastSeenAt)}</td>
                            <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">{row.loginCount}</td>
                            <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">{row.queryCount}</td>
                            <td className="px-4 py-3">
                              {row.banned ? (
                                <span className="font-semibold text-red-600 dark:text-red-400">{t('IP Yasaklı', 'IP Banned')}</span>
                              ) : (
                                <span className="font-semibold text-emerald-600 dark:text-emerald-400">{t('İzinli', 'Allowed')}</span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-right whitespace-nowrap">
                              <button
                                type="button"
                                disabled={managerBusy}
                                onClick={() => handleToggleAdminIpBan(row.ip, !row.banned)}
                                className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-semibold disabled:opacity-50 ${
                                  row.banned
                                    ? 'border-emerald-300 text-emerald-700 hover:bg-emerald-50 dark:border-emerald-800 dark:text-emerald-400 dark:hover:bg-emerald-950/30'
                                    : 'border-red-300 text-red-600 hover:bg-red-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950/40'
                                }`}
                              >
                                <Ban className="h-3 w-3" />
                                <span>{row.banned ? t('IP Yasağını Kaldır', 'Unban IP') : t('IP Yasakla', 'Ban IP')}</span>
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}
        </>
      )}

      <DatasetEditorModal
        dataset={editingDataset}
        onClose={() => setEditingDataset(null)}
        onDatasetChanged={async (datasetId) => {
          await Promise.all([loadOverview(), onStatsChanged()]);
          if (isRootManager) void onRequestCloudSync?.({ restoreMissing: false, forceDatasetIds: [datasetId] });
        }}
      />
    </div>
  );
}
