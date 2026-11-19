import { parentPort, workerData } from 'node:worker_threads';
import type { FieldMapping } from '../src/types/intel.ts';
import { analyzeRawFileToDiskDataset, DiskIndex } from './diskIndex.ts';

interface IngestWorkerData {
  dataDir: string;
  datasetId: string;
  datasetName: string;
  rawFilePath: string;
  shardPath: string;
  format: 'json' | 'csv' | 'ndjson' | 'text';
  columns: string[];
  mapping: FieldMapping;
  delimiter?: string;
  hasHeader?: boolean;
  isHeterogeneous?: boolean;
}

const data = workerData as IngestWorkerData;
const controller = new AbortController();

parentPort?.on('message', (msg: { type?: string }) => {
  if (msg && msg.type === 'abort') {
    controller.abort();
  }
});

const diskIndex = new DiskIndex(data.dataDir);

analyzeRawFileToDiskDataset({
  datasetId: data.datasetId,
  datasetName: data.datasetName,
  rawFilePath: data.rawFilePath,
  shardPath: data.shardPath,
  format: data.format,
  columns: data.columns,
  mapping: data.mapping,
  delimiter: data.delimiter,
  hasHeader: data.hasHeader,
  isHeterogeneous: data.isHeterogeneous,
  diskIndex,
  signal: controller.signal,
  onProgress: (recordCount, writtenBytes) => {
    parentPort?.postMessage({ type: 'progress', recordCount, writtenBytes });
  },
})
  .then((result) => {
    parentPort?.postMessage({ type: 'done', result });
    parentPort?.close();
  })
  .catch((err) => {
    parentPort?.postMessage({
      type: 'error',
      message: err instanceof Error ? err.message : 'Veri analizi başarısız oldu.',
    });
    parentPort?.close();
  });
