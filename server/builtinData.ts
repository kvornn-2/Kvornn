import type { DatasetMeta, IntelRecord } from '../src/types/intel.ts';

export interface BuiltinDatasetSeed {
  meta: DatasetMeta;
  records: IntelRecord[];
}

/**
 * Uygulama içine doğrudan gömülü (yerleşik), filtrelenmiş OSINT ve ID kayıtları.
 * Sunucu ilk kez veya boş veri diziniyle başladığında ServerStore tarafından
 * otomatik olarak veritabanına yüklenir ve sorgulanabilir hale gelir.
 */
export const BUILTIN_SEED_DATASETS: BuiltinDatasetSeed[] = [];
