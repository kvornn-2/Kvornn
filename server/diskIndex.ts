import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import type { FieldMapping, IntelRecord } from '../src/types/intel.ts';
import {
  classifyRecordDatabaseType,
  collectRecordTokens,
} from '../src/utils/search.ts';
import {
  buildMappedFieldSet,
  cleanInvisibleChars,
  createCsvColumnPlan,
  flattenObject,
  isStandardHeteroMapping,
  normalizeCsvCellsDirect,
  normalizeSingleRow,
  parseCsvLineFast,
  parseMixedLineToIntelRecord,
  splitSqlTuples,
} from '../src/utils/parser.ts';

const NUM_BUCKETS = 256;
const NON_ASCII_RE = /[^\x00-\x7f]/;
const INVISIBLE_CHUNK_TEST_RE = /[\u200B-\u200D\uFEFF]/;

function utf8ByteLengthFast(str: string): number {
  return NON_ASCII_RE.test(str) ? Buffer.byteLength(str, 'utf8') : str.length;
}

function fnv1a32(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function sanitizeIndexKey(raw: string): string {
  if (!raw) return '';
  if (raw.indexOf('\t') !== -1 || raw.indexOf('\n') !== -1 || raw.indexOf('\r') !== -1) {
    return raw.replace(/[\t\r\n]/g, ' ').trim();
  }
  return raw.trim();
}

export class DiskIndexWriter {
  private readonly indexDir: string;
  private readonly buckets: string[][] = Array.from({ length: NUM_BUCKETS }, () => []);
  private readonly bucketFds = new Int32Array(NUM_BUCKETS).fill(-1);
  private readonly seenRecordTokens = new Set<string>();
  private bufferedCount = 0;
  private readonly flushThreshold: number;
  private dirEnsured = false;

  constructor(indexDir: string, flushThreshold = 200_000) {
    this.indexDir = indexDir;
    this.flushThreshold = flushThreshold;
    if (!fs.existsSync(this.indexDir)) {
      fs.mkdirSync(this.indexDir, { recursive: true });
    }
    this.dirEnsured = true;
  }

  private addTokenWithMeta(typedKey: string, metaSuffix: string) {
    const cleanKey = sanitizeIndexKey(typedKey);
    if (!cleanKey) return;
    const bucketIdx = fnv1a32(cleanKey) & 0xff;
    this.buckets[bucketIdx].push(cleanKey + metaSuffix);
    this.bufferedCount += 1;
    if (this.bufferedCount >= this.flushThreshold) {
      this.flush();
    }
  }

  addToken(typedKey: string, datasetId: string, byteOffset: number, byteLength: number) {
    const cleanKey = sanitizeIndexKey(typedKey);
    if (!cleanKey) return;
    const bucketIdx = fnv1a32(cleanKey) & 0xff;
    this.buckets[bucketIdx].push(`${cleanKey}\t${datasetId}\t${byteOffset}\t${byteLength}\n`);
    this.bufferedCount += 1;
    if (this.bufferedCount >= this.flushThreshold) {
      this.flush();
    }
  }

  indexRecord(rec: IntelRecord, datasetId: string, byteOffset: number, byteLength: number) {
    const metaSuffix = `\t${datasetId}\t${byteOffset}\t${byteLength}\n`;
    collectRecordTokens(rec, this.seenRecordTokens, (typedKey) => {
      this.addTokenWithMeta(typedKey, metaSuffix);
    });
  }

  flush() {
    if (this.bufferedCount === 0) return;
    if (!this.dirEnsured || !fs.existsSync(this.indexDir)) {
      fs.mkdirSync(this.indexDir, { recursive: true });
      this.dirEnsured = true;
    }
    for (let b = 0; b < NUM_BUCKETS; b++) {
      const lines = this.buckets[b];
      if (lines.length === 0) continue;
      let fd = this.bucketFds[b];
      if (fd === -1) {
        const bucketPath = path.join(this.indexDir, `b_${b.toString(16).padStart(2, '0')}.tsv`);
        fd = fs.openSync(bucketPath, 'a', 0o600);
        this.bucketFds[b] = fd;
      }
      const payload = Buffer.from(lines.join(''), 'utf8');
      fs.writeSync(fd, payload, 0, payload.length);
      this.buckets[b] = [];
    }
    this.bufferedCount = 0;
  }

  close() {
    try {
      this.flush();
    } finally {
      for (let b = 0; b < NUM_BUCKETS; b++) {
        const fd = this.bucketFds[b];
        if (fd !== -1) {
          this.bucketFds[b] = -1;
          try {
            fs.closeSync(fd);
          } catch {
            // Ignore close errors
          }
        }
      }
    }
  }
}

export interface DiskPosting {
  datasetId: string;
  byteOffset: number;
  byteLength: number;
}

export class DiskIndex {
  readonly indexDir: string;

  constructor(dataDir: string) {
    this.indexDir = path.join(dataDir, 'index');
    if (!fs.existsSync(this.indexDir)) {
      fs.mkdirSync(this.indexDir, { recursive: true });
    }
  }

  createWriter(flushThreshold = 200_000): DiskIndexWriter {
    return new DiskIndexWriter(this.indexDir, flushThreshold);
  }

  hasAnyIndexFiles(): boolean {
    if (!fs.existsSync(this.indexDir)) return false;
    try {
      const files = fs.readdirSync(this.indexDir);
      return files.some((f) => f.endsWith('.tsv'));
    } catch {
      return false;
    }
  }

  clearAll() {
    if (!fs.existsSync(this.indexDir)) return;
    try {
      fs.rmSync(this.indexDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
    fs.mkdirSync(this.indexDir, { recursive: true });
  }

  private parsePostingLine(
    rest: string,
    activeDatasetIds: Set<string>,
    seenOffsetKeys: Set<string>,
    postings: DiskPosting[],
  ) {
    const t1 = rest.indexOf('\t');
    const t2 = t1 !== -1 ? rest.indexOf('\t', t1 + 1) : -1;
    if (t1 !== -1 && t2 !== -1) {
      const dsId = rest.slice(0, t1);
      if (activeDatasetIds.has(dsId)) {
        const off = Number(rest.slice(t1 + 1, t2));
        const len = Number(rest.slice(t2 + 1));
        if (Number.isFinite(off) && Number.isFinite(len) && len > 0) {
          const dedupKey = `${dsId}:${off}`;
          if (!seenOffsetKeys.has(dedupKey)) {
            seenOffsetKeys.add(dedupKey);
            postings.push({ datasetId: dsId, byteOffset: off, byteLength: len });
          }
        }
      }
    }
  }

  private scanCompleteBufferSlice(
    activeSlice: Buffer,
    prefixBufs: Buffer[],
    activeDatasetIds: Set<string>,
    seenOffsetKeys: Set<string>,
    postings: DiskPosting[],
    maxTotal: number,
  ): boolean {
    const sliceLen = activeSlice.length;
    for (let p = 0; p < prefixBufs.length; p++) {
      const needle = prefixBufs[p];
      let pos = 0;
      while (pos < sliceLen) {
        const hitIdx = activeSlice.indexOf(needle, pos);
        if (hitIdx === -1) break;
        if (hitIdx === 0 || activeSlice[hitIdx - 1] === 0x0a) {
          const restStart = hitIdx + needle.length;
          const lineEnd = activeSlice.indexOf(0x0a, restStart);
          const restEnd = lineEnd !== -1 ? lineEnd : sliceLen;
          const rest = activeSlice.toString('utf8', restStart, restEnd);
          this.parsePostingLine(rest, activeDatasetIds, seenOffsetKeys, postings);
          if (postings.length >= maxTotal) return true;
        }
        pos = hitIdx + needle.length;
      }
    }
    return false;
  }

  private scanBucketPrefixesSync(
    bucketIdx: number,
    prefixes: string[],
    activeDatasetIds: Set<string>,
    maxTotal: number,
  ): DiskPosting[] {
    const bucketPath = path.join(this.indexDir, `b_${bucketIdx.toString(16).padStart(2, '0')}.tsv`);
    if (!fs.existsSync(bucketPath)) return [];

    const postings: DiskPosting[] = [];
    const seenOffsetKeys = new Set<string>();
    const prefixBufs = prefixes.map((p) => Buffer.from(p, 'utf8'));
    const CHUNK_SIZE = 2 * 1024 * 1024;
    const CARRY_PAD = 64 * 1024;
    const buf = Buffer.allocUnsafe(CHUNK_SIZE + CARRY_PAD);
    const fd = fs.openSync(bucketPath, 'r');
    let carryoverLen = 0;

    try {
      while (true) {
        const maxRead = buf.length - carryoverLen;
        const readAmt = Math.min(CHUNK_SIZE, maxRead);
        const bytesRead = fs.readSync(fd, buf, carryoverLen, readAmt, null);
        if (bytesRead === 0) break;

        const validLen = carryoverLen + bytesRead;
        const lastNl = buf.lastIndexOf(0x0a, validLen - 1);
        if (lastNl === -1) {
          carryoverLen = validLen < buf.length ? validLen : 0;
          continue;
        }

        const activeSlice = buf.subarray(0, lastNl + 1);
        if (
          this.scanCompleteBufferSlice(
            activeSlice,
            prefixBufs,
            activeDatasetIds,
            seenOffsetKeys,
            postings,
            maxTotal,
          )
        ) {
          return postings;
        }

        carryoverLen = validLen - (lastNl + 1);
        if (carryoverLen > 0) {
          buf.copy(buf, 0, lastNl + 1, validLen);
        }
      }

      if (carryoverLen > 0) {
        const tail = buf.subarray(0, carryoverLen).toString('utf8').trim();
        if (tail) {
          for (let p = 0; p < prefixes.length; p++) {
            const prefix = prefixes[p];
            if (tail.startsWith(prefix)) {
              this.parsePostingLine(tail.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
              break;
            }
          }
        }
      }
    } finally {
      fs.closeSync(fd);
    }

    return postings;
  }

  private async scanBucketPrefixesAsync(
    bucketIdx: number,
    prefixes: string[],
    activeDatasetIds: Set<string>,
    maxTotal: number,
  ): Promise<DiskPosting[]> {
    const bucketPath = path.join(this.indexDir, `b_${bucketIdx.toString(16).padStart(2, '0')}.tsv`);
    let handle: fs.promises.FileHandle;
    try {
      handle = await fs.promises.open(bucketPath, 'r');
    } catch {
      return [];
    }

    const postings: DiskPosting[] = [];
    const seenOffsetKeys = new Set<string>();
    const prefixBufs = prefixes.map((p) => Buffer.from(p, 'utf8'));
    const CHUNK_SIZE = 2 * 1024 * 1024;
    const CARRY_PAD = 64 * 1024;
    const buf = Buffer.allocUnsafe(CHUNK_SIZE + CARRY_PAD);
    let carryoverLen = 0;
    let filePos = 0;

    try {
      while (true) {
        const maxRead = buf.length - carryoverLen;
        const readAmt = Math.min(CHUNK_SIZE, maxRead);
        const { bytesRead } = await handle.read(buf, carryoverLen, readAmt, filePos);
        if (bytesRead === 0) break;
        filePos += bytesRead;

        const validLen = carryoverLen + bytesRead;
        const lastNl = buf.lastIndexOf(0x0a, validLen - 1);
        if (lastNl === -1) {
          carryoverLen = validLen < buf.length ? validLen : 0;
          continue;
        }

        const activeSlice = buf.subarray(0, lastNl + 1);
        if (
          this.scanCompleteBufferSlice(
            activeSlice,
            prefixBufs,
            activeDatasetIds,
            seenOffsetKeys,
            postings,
            maxTotal,
          )
        ) {
          return postings;
        }

        carryoverLen = validLen - (lastNl + 1);
        if (carryoverLen > 0) {
          buf.copy(buf, 0, lastNl + 1, validLen);
        }
      }

      if (carryoverLen > 0) {
        const tail = buf.subarray(0, carryoverLen).toString('utf8').trim();
        if (tail) {
          for (let p = 0; p < prefixes.length; p++) {
            const prefix = prefixes[p];
            if (tail.startsWith(prefix)) {
              this.parsePostingLine(tail.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
              break;
            }
          }
        }
      }
    } finally {
      await handle.close().catch(() => {});
    }

    return postings;
  }

  lookupPostings(typedKey: string, activeDatasetIds: Set<string>, maxHits = 20000): DiskPosting[] {
    const cleanKey = sanitizeIndexKey(typedKey);
    if (!cleanKey || activeDatasetIds.size === 0) return [];
    const bucketIdx = fnv1a32(cleanKey) & 0xff;
    return this.scanBucketPrefixesSync(bucketIdx, [`${cleanKey}\t`], activeDatasetIds, maxHits);
  }

  readRecordsByPostings(
    postings: DiskPosting[],
    resolveShardPath: (datasetId: string) => string,
  ): IntelRecord[] {
    if (postings.length === 0) return [];
    const results: IntelRecord[] = [];
    const openFds = new Map<string, number>();

    try {
      for (let i = 0; i < postings.length; i++) {
        const p = postings[i];
        let fd = openFds.get(p.datasetId);
        if (fd === undefined) {
          const shardPath = resolveShardPath(p.datasetId);
          if (!fs.existsSync(shardPath)) continue;
          fd = fs.openSync(shardPath, 'r');
          openFds.set(p.datasetId, fd);
        }
        const safeLen = Math.min(4 * 1024 * 1024, Math.max(2, p.byteLength));
        const readBuf = Buffer.allocUnsafe(safeLen);
        const n = fs.readSync(fd, readBuf, 0, safeLen, p.byteOffset);
        if (n <= 0) continue;
        const line = readBuf.subarray(0, n).toString('utf8').trim();
        if (!line) continue;
        try {
          const parsed = JSON.parse(line) as IntelRecord;
          if (parsed && typeof parsed === 'object' && parsed.id) {
            parsed.dbType = classifyRecordDatabaseType(parsed);
            results.push(parsed);
          }
        } catch {
          // Ignore malformed line
        }
      }
    } finally {
      for (const fd of openFds.values()) {
        try {
          fs.closeSync(fd);
        } catch {
          // Ignore close error
        }
      }
    }

    return results;
  }

  async readRecordsByPostingsAsync(
    postings: DiskPosting[],
    resolveShardPath: (datasetId: string) => string,
  ): Promise<IntelRecord[]> {
    if (postings.length === 0) return [];
    const results: IntelRecord[] = [];
    const openHandles = new Map<string, fs.promises.FileHandle | null>();

    try {
      for (let i = 0; i < postings.length; i++) {
        const p = postings[i];
        let handle = openHandles.get(p.datasetId);
        if (handle === undefined) {
          const shardPath = resolveShardPath(p.datasetId);
          try {
            handle = await fs.promises.open(shardPath, 'r');
          } catch {
            handle = null;
          }
          openHandles.set(p.datasetId, handle);
        }
        if (!handle) continue;

        const safeLen = Math.min(4 * 1024 * 1024, Math.max(2, p.byteLength));
        const readBuf = Buffer.allocUnsafe(safeLen);
        const { bytesRead } = await handle.read(readBuf, 0, safeLen, p.byteOffset);
        if (bytesRead <= 0) continue;
        const line = readBuf.subarray(0, bytesRead).toString('utf8').trim();
        if (!line) continue;
        try {
          const parsed = JSON.parse(line) as IntelRecord;
          if (parsed && typeof parsed === 'object' && parsed.id) {
            parsed.dbType = classifyRecordDatabaseType(parsed);
            results.push(parsed);
          }
        } catch {
          // Ignore malformed line
        }
        if (i > 0 && i % 200 === 0) {
          await new Promise<void>((r) => setImmediate(r));
        }
      }
    } finally {
      for (const handle of openHandles.values()) {
        if (handle) {
          await handle.close().catch(() => {});
        }
      }
    }

    return results;
  }

  private groupPrefixesByBucket(typedKeys: string[]): Map<number, string[]> {
    const byBucket = new Map<number, Set<string>>();
    for (let i = 0; i < typedKeys.length; i++) {
      const cleanKey = sanitizeIndexKey(typedKeys[i]);
      if (!cleanKey) continue;
      const bucketIdx = fnv1a32(cleanKey) & 0xff;
      let prefixSet = byBucket.get(bucketIdx);
      if (!prefixSet) {
        prefixSet = new Set<string>();
        byBucket.set(bucketIdx, prefixSet);
      }
      prefixSet.add(`${cleanKey}\t`);
    }
    const grouped = new Map<number, string[]>();
    for (const [b, set] of byBucket.entries()) {
      grouped.set(b, Array.from(set));
    }
    return grouped;
  }

  lookupRecords(
    typedKeys: string[],
    activeDatasetIds: Set<string>,
    resolveShardPath: (datasetId: string) => string,
    maxPerKey = 10000,
  ): IntelRecord[] {
    if (typedKeys.length === 0 || activeDatasetIds.size === 0) return [];
    const grouped = this.groupPrefixesByBucket(typedKeys);
    const allPostings: DiskPosting[] = [];
    const seenPosting = new Set<string>();

    for (const [bucketIdx, prefixes] of grouped.entries()) {
      const maxBucketHits = Math.min(50_000, maxPerKey * prefixes.length);
      const hits = this.scanBucketPrefixesSync(bucketIdx, prefixes, activeDatasetIds, maxBucketHits);
      for (let j = 0; j < hits.length; j++) {
        const h = hits[j];
        const k = `${h.datasetId}:${h.byteOffset}`;
        if (!seenPosting.has(k)) {
          seenPosting.add(k);
          allPostings.push(h);
        }
      }
    }

    return this.readRecordsByPostings(allPostings, resolveShardPath);
  }

  async lookupRecordsAsync(
    typedKeys: string[],
    activeDatasetIds: Set<string>,
    resolveShardPath: (datasetId: string) => string,
    maxPerKey = 10000,
  ): Promise<IntelRecord[]> {
    if (typedKeys.length === 0 || activeDatasetIds.size === 0) return [];
    const grouped = this.groupPrefixesByBucket(typedKeys);
    const bucketEntries = Array.from(grouped.entries());
    const allPostings: DiskPosting[] = [];
    const seenPosting = new Set<string>();

    // Scan buckets with bounded concurrency so concurrent queries interleave smoothly
    const BUCKET_CONCURRENCY = 4;
    for (let i = 0; i < bucketEntries.length; i += BUCKET_CONCURRENCY) {
      const slice = bucketEntries.slice(i, i + BUCKET_CONCURRENCY);
      const batchResults = await Promise.all(
        slice.map(([bucketIdx, prefixes]) =>
          this.scanBucketPrefixesAsync(
            bucketIdx,
            prefixes,
            activeDatasetIds,
            Math.min(50_000, maxPerKey * prefixes.length),
          ),
        ),
      );
      for (let b = 0; b < batchResults.length; b++) {
        const hits = batchResults[b];
        for (let j = 0; j < hits.length; j++) {
          const h = hits[j];
          const k = `${h.datasetId}:${h.byteOffset}`;
          if (!seenPosting.has(k)) {
            seenPosting.add(k);
            allPostings.push(h);
          }
        }
      }
    }

    return this.readRecordsByPostingsAsync(allPostings, resolveShardPath);
  }
}

export function indexRecordBatchToDisk(
  writer: DiskIndexWriter,
  shardPath: string,
  records: IntelRecord[],
  appendMode: boolean,
): number {
  if (records.length === 0 && appendMode) {
    writer.close();
    return 0;
  }
  const dir = path.dirname(shardPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  let startOffset = 0;
  if (appendMode && fs.existsSync(shardPath)) {
    startOffset = fs.statSync(shardPath).size;
  }

  const fd = fs.openSync(shardPath, appendMode ? 'a' : 'w', 0o600);
  let totalWritten = 0;
  try {
    let cursor = startOffset;
    const CHUNK = 4000;
    for (let i = 0; i < records.length; i += CHUNK) {
      const end = Math.min(records.length, i + CHUNK);
      const parts: string[] = [];
      let blockBytes = 0;
      for (let j = i; j < end; j++) {
        const rec = records[j];
        const line = `${JSON.stringify(rec)}\n`;
        const lineBytes = utf8ByteLengthFast(line);
        writer.indexRecord(rec, rec.datasetId, cursor, lineBytes);
        cursor += lineBytes;
        blockBytes += lineBytes;
        parts.push(line);
      }
      const payload = Buffer.from(parts.join(''), 'utf8');
      totalWritten += blockBytes;
      fs.writeSync(fd, payload, 0, payload.length);
    }
  } finally {
    fs.closeSync(fd);
    writer.close();
  }
  return totalWritten;
}

export function iterateShardRecordsSync(
  shardPath: string,
  onRecord: (rec: IntelRecord) => boolean | void,
) {
  if (!fs.existsSync(shardPath)) return;
  const CHUNK_SIZE = 512 * 1024;
  const buf = Buffer.allocUnsafe(CHUNK_SIZE);
  const fd = fs.openSync(shardPath, 'r');
  const decoder = new StringDecoder('utf8');
  let leftover = '';

  try {
    let bytesRead = 0;
    while ((bytesRead = fs.readSync(fd, buf, 0, CHUNK_SIZE, null)) > 0) {
      const text = leftover + decoder.write(buf.subarray(0, bytesRead));
      let start = 0;
      let nl = text.indexOf('\n', start);
      while (nl !== -1) {
        const line = text.slice(start, nl).trim();
        start = nl + 1;
        if (line) {
          try {
            const parsed = JSON.parse(line) as IntelRecord;
            if (parsed && typeof parsed === 'object' && parsed.id) {
              const cont = onRecord(parsed);
              if (cont === false) return;
            }
          } catch {
            // Skip malformed line
          }
        }
        nl = text.indexOf('\n', start);
      }
      leftover = text.slice(start);
    }

    const tail = (leftover + decoder.end()).trim();
    if (tail) {
      try {
        const parsed = JSON.parse(tail) as IntelRecord;
        if (parsed && typeof parsed === 'object' && parsed.id) {
          onRecord(parsed);
        }
      } catch {
        // Ignore
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

export interface StreamIngestionOptions {
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
  diskIndex: DiskIndex;
  signal?: AbortSignal;
  onProgress?: (processedCount: number, writtenBytes: number) => void;
}

export async function analyzeRawFileToDiskDataset(
  opts: StreamIngestionOptions,
): Promise<{ recordCount: number; shardBytes: number; columns: string[] }> {
  const {
    datasetId,
    datasetName,
    rawFilePath,
    shardPath,
    format,
    mapping,
    delimiter = ',',
    hasHeader = false,
    isHeterogeneous = false,
    diskIndex,
    signal,
    onProgress,
  } = opts;

  const colSet = new Set<string>(opts.columns || []);
  const mappedFields = buildMappedFieldSet(mapping);
  const isStdHetero = isStandardHeteroMapping(mapping);
  const indexWriter = diskIndex.createWriter(250_000);

  const tmpShardPath = `${shardPath}.ingest.tmp`;
  const shardDir = path.dirname(shardPath);
  if (!fs.existsSync(shardDir)) {
    fs.mkdirSync(shardDir, { recursive: true });
  }

  const outFd = fs.openSync(tmpShardPath, 'w', 0o600);
  let byteCursor = 0;
  let recordCount = 0;
  let shardChunks: string[] = [];
  let shardBufferedBytes = 0;
  let lastProgressAt = performance.now();
  const SHARD_FLUSH_BYTES = 4 * 1024 * 1024;

  const flushShardBlock = () => {
    if (shardChunks.length === 0) return;
    const payload = Buffer.from(shardChunks.join(''), 'utf8');
    fs.writeSync(outFd, payload, 0, payload.length);
    shardChunks = [];
    shardBufferedBytes = 0;
  };

  const emitNormalizedRecord = (rec: IntelRecord) => {
    const jsonLine = `${JSON.stringify(rec)}\n`;
    const lineBytes = utf8ByteLengthFast(jsonLine);
    indexWriter.indexRecord(rec, datasetId, byteCursor, lineBytes);
    byteCursor += lineBytes;
    shardChunks.push(jsonLine);
    shardBufferedBytes += lineBytes;
    recordCount += 1;

    if (shardBufferedBytes >= SHARD_FLUSH_BYTES) {
      flushShardBlock();
    }
    if ((recordCount & 16383) === 0) {
      const now = performance.now();
      if (now - lastProgressAt >= 400) {
        lastProgressAt = now;
        onProgress?.(recordCount, byteCursor);
      }
    }
  };

  const emitRow = (row: Record<string, string>, skipInvisibleCheck = false) => {
    const rec = normalizeSingleRow(row, mapping, datasetId, datasetName, recordCount, mappedFields, skipInvisibleCheck);
    emitNormalizedRecord(rec);
  };

  const yieldEventLoop = () => new Promise<void>((resolve) => setImmediate(resolve));

  const handle = await fs.promises.open(rawFilePath, 'r');
  try {
    // Peek first 2 KB to detect JSON array vs NDJSON vs SQL vs Line-delimited accurately
    const peekBuf = Buffer.allocUnsafe(2048);
    const peekRead = await handle.read(peekBuf, 0, 2048, 0);
    const peekText = peekBuf.subarray(0, peekRead.bytesRead).toString('utf8').replace(/^\uFEFF/, '');
    const peekTrimmed = peekText.trimStart();

    const isSqlDump =
      format === 'text' && /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?/i.test(peekText);
    const isJsonContainer =
      (format === 'json' || peekTrimmed.startsWith('[')) &&
      (peekTrimmed.startsWith('[') ||
        /^\{\s*"(?:data|records|users|items|rows|results|entries)"\s*:\s*\[/i.test(peekTrimmed));

    const READ_CHUNK = 4 * 1024 * 1024;
    const readBuf = Buffer.allocUnsafe(READ_CHUNK);
    const decoder = new StringDecoder('utf8');
    let filePos = 0;

    if (isJsonContainer) {
      // Streaming top-level JSON object extractor — handles multi-GB JSON arrays in O(1) RAM
      let inStr = false;
      let escaped = false;
      let depth = 0;
      const targetDepth = peekTrimmed.startsWith('{') ? 2 : 1;
      let capturing = false;
      let objBuffer = '';
      let firstChunk = true;

      while (true) {
        if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
        const { bytesRead } = await handle.read(readBuf, 0, READ_CHUNK, filePos);
        if (bytesRead === 0) break;
        filePos += bytesRead;
        let text = decoder.write(readBuf.subarray(0, bytesRead));
        if (firstChunk) {
          text = text.replace(/^\uFEFF/, '');
          firstChunk = false;
        }
        const skipInvis = !INVISIBLE_CHUNK_TEST_RE.test(text);

        let segmentStart = 0;
        for (let i = 0; i < text.length; i++) {
          const ch = text.charCodeAt(i);
          if (inStr) {
            if (escaped) escaped = false;
            else if (ch === 92) escaped = true; // '\'
            else if (ch === 34) inStr = false; // '"'
            continue;
          }
          if (ch === 34) {
            inStr = true;
            continue;
          }
          if (ch === 123) {
            // '{'
            depth += 1;
            if (depth === targetDepth && !capturing) {
              capturing = true;
              segmentStart = i;
              objBuffer = '';
            }
          } else if (ch === 125) {
            // '}'
            if (capturing && depth === targetDepth) {
              objBuffer += text.slice(segmentStart, i + 1);
              capturing = false;
              try {
                const parsed = JSON.parse(objBuffer) as unknown;
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                  const flat = flattenObject(parsed as Record<string, unknown>);
                  if (colSet.size < 50) {
                    for (const k in flat) {
                      if (!Object.prototype.hasOwnProperty.call(flat, k)) continue;
                      colSet.add(k);
                      if (colSet.size >= 50) break;
                    }
                  }
                  emitRow(flat, skipInvis);
                }
              } catch {
                // Skip malformed JSON object
              }
              objBuffer = '';
            }
            depth = Math.max(0, depth - 1);
          }
        }
        if (capturing) {
          objBuffer += text.slice(segmentStart);
          if (objBuffer.length > 16 * 1024 * 1024) {
            capturing = false;
            objBuffer = '';
          }
        }
        await yieldEventLoop();
      }
      decoder.end();
    } else if (isSqlDump) {
      // Streaming SQL INSERT statement parser
      let sqlBuffer = '';
      let firstChunk = true;
      const headerRe = /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?(?:\s*\(([^)]+)\))?\s+VALUES\s*/i;

      const processSqlStatementSync = (stmt: string, skipInvis: boolean) => {
        const match = headerRe.exec(stmt);
        if (!match) return;
        const rawCols = match[1]
          ? match[1]
              .split(',')
              .map((c) => c.replace(/[`"\[\]\s]/g, ''))
              .filter(Boolean)
          : null;
        const valuesSlice = stmt.slice(match.index + match[0].length);
        const tuples = splitSqlTuples(valuesSlice);
        for (let t = 0; t < tuples.length; t++) {
          if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
          const tuple = tuples[t];
          const rowObj: Record<string, string> = {};
          for (let idx = 0; idx < tuple.length; idx++) {
            const colName = (rawCols && rawCols[idx]) || `sutun_${idx + 1}`;
            if (colSet.size < 50) colSet.add(colName);
            const rawVal = tuple[idx] || '';
            rowObj[colName] = skipInvis ? rawVal.trim() : cleanInvisibleChars(rawVal);
          }
          emitRow(rowObj, skipInvis);
        }
      };

      while (true) {
        if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
        const { bytesRead } = await handle.read(readBuf, 0, READ_CHUNK, filePos);
        if (bytesRead === 0) break;
        filePos += bytesRead;
        let text = decoder.write(readBuf.subarray(0, bytesRead));
        if (firstChunk) {
          text = text.replace(/^\uFEFF/, '');
          firstChunk = false;
        }
        sqlBuffer += text;
        const skipInvis = !INVISIBLE_CHUNK_TEST_RE.test(sqlBuffer);

        let semiIdx = sqlBuffer.indexOf(';');
        while (semiIdx !== -1) {
          const stmt = sqlBuffer.slice(0, semiIdx);
          sqlBuffer = sqlBuffer.slice(semiIdx + 1);
          processSqlStatementSync(stmt, skipInvis);
          semiIdx = sqlBuffer.indexOf(';');
        }
        await yieldEventLoop();
      }
      sqlBuffer += decoder.end();
      if (sqlBuffer.trim()) {
        processSqlStatementSync(sqlBuffer, !INVISIBLE_CHUNK_TEST_RE.test(sqlBuffer));
      }
    } else {
      // Streaming Line-by-Line Reader (CSV, TSV, Colon, ULP, NDJSON, Mixed Text, Logs)
      let leftover = '';
      let lineIndex = 0;
      let firstChunk = true;
      const baseColumns = opts.columns || [];
      let maxTrackedCols = baseColumns.length;
      const colPlan = createCsvColumnPlan(baseColumns, mapping, mappedFields);

      const processLineSync = (rawLine: string, skipInvis: boolean) => {
        if (!rawLine) return;
        const line = skipInvis ? rawLine.trim() : cleanInvisibleChars(rawLine);
        if (!line) return;
        const currentLineNo = lineIndex;
        lineIndex += 1;

        if (currentLineNo === 0 && hasHeader) {
          return;
        }

        const startsWithBrace = line.charCodeAt(0) === 123;
        if (format === 'ndjson' || (startsWithBrace && line.charCodeAt(line.length - 1) === 125)) {
          try {
            const obj = JSON.parse(line) as unknown;
            if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
              const flat = flattenObject(obj as Record<string, unknown>);
              if (colSet.size < 50) {
                for (const k in flat) {
                  if (!Object.prototype.hasOwnProperty.call(flat, k)) continue;
                  colSet.add(k);
                  if (colSet.size >= 50) break;
                }
              }
              emitRow(flat, skipInvis);
              return;
            }
          } catch {
            // Fall through to mixed-line parser
          }
        }

        if (isHeterogeneous) {
          const rec = parseMixedLineToIntelRecord(
            line,
            mapping,
            datasetId,
            datasetName,
            recordCount,
            isStdHetero,
            mappedFields,
            skipInvis,
          );
          emitNormalizedRecord(rec);
          return;
        }

        const cells = parseCsvLineFast(line, delimiter);
        let anyNonEmpty = false;
        for (let i = 0; i < cells.length; i++) {
          if (cells[i]) {
            anyNonEmpty = true;
            break;
          }
        }
        if (!anyNonEmpty) return;

        if (cells.length > maxTrackedCols && colSet.size < 50) {
          for (let c = maxTrackedCols; c < cells.length && colSet.size < 50; c++) {
            colSet.add(`sutun_${c + 1}`);
          }
          maxTrackedCols = cells.length;
        }

        const rec = normalizeCsvCellsDirect(
          cells,
          colPlan,
          mappedFields,
          datasetId,
          datasetName,
          recordCount,
          skipInvis,
        );
        emitNormalizedRecord(rec);
      };

      while (true) {
        if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
        const { bytesRead } = await handle.read(readBuf, 0, READ_CHUNK, filePos);
        if (bytesRead === 0) break;
        filePos += bytesRead;
        let text = leftover + decoder.write(readBuf.subarray(0, bytesRead));
        if (firstChunk) {
          text = text.replace(/^\uFEFF/, '');
          firstChunk = false;
        }
        const skipInvis = !INVISIBLE_CHUNK_TEST_RE.test(text);

        let start = 0;
        let nl = text.indexOf('\n', start);
        while (nl !== -1) {
          let lineEnd = nl;
          if (lineEnd > start && text.charCodeAt(lineEnd - 1) === 13) {
            lineEnd -= 1;
          }
          const line = text.slice(start, lineEnd);
          start = nl + 1;
          processLineSync(line, skipInvis);
          nl = text.indexOf('\n', start);
        }
        leftover = text.slice(start);
        await yieldEventLoop();
      }

      const tail = leftover + decoder.end();
      if (tail.trim()) {
        processLineSync(tail, !INVISIBLE_CHUNK_TEST_RE.test(tail));
      }
    }

    if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
    flushShardBlock();
    indexWriter.close();
    fs.closeSync(outFd);
    fs.renameSync(tmpShardPath, shardPath);
    onProgress?.(recordCount, byteCursor);

    return {
      recordCount,
      shardBytes: byteCursor,
      columns: Array.from(colSet).slice(0, 50),
    };
  } catch (err) {
    try {
      fs.closeSync(outFd);
    } catch {
      // Ignore
    }
    try {
      if (fs.existsSync(tmpShardPath)) fs.unlinkSync(tmpShardPath);
    } catch {
      // Ignore
    }
    throw err;
  } finally {
    try {
      indexWriter.close();
    } catch {
      // Ignore
    }
    await handle.close().catch(() => {});
  }
}
