import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import type { FieldMapping, IntelRecord } from '../src/types/intel.ts';
import {
  buildMappedFieldSet,
  cleanInvisibleChars,
  flattenObject,
  normalizeSingleRow,
  parseCsvLine,
  parseMixedSingleLine,
  splitSqlTuples,
} from '../src/utils/parser.ts';
import {
  classifyRecordDatabaseType,
  extractRecordEmails,
  extractRecordExtraIdentifiers,
  extractRecordIps,
  extractRecordPhones,
  extractRecordSnowflakes,
  extractRecordUsernames,
} from '../src/utils/search.ts';

const NUM_BUCKETS = 256;

function fnv1a32(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function sanitizeIndexKey(raw: string): string {
  return raw.replace(/[\t\r\n]/g, ' ').trim();
}

export class DiskIndexWriter {
  private readonly indexDir: string;
  private readonly buckets: string[][] = Array.from({ length: NUM_BUCKETS }, () => []);
  private bufferedCount = 0;
  private readonly flushThreshold: number;

  constructor(indexDir: string, flushThreshold = 4096) {
    this.indexDir = indexDir;
    this.flushThreshold = flushThreshold;
    if (!fs.existsSync(this.indexDir)) {
      fs.mkdirSync(this.indexDir, { recursive: true });
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
    const snowflakes = extractRecordSnowflakes(rec);
    for (let i = 0; i < snowflakes.length; i++) {
      this.addToken(`id:${snowflakes[i]}`, datasetId, byteOffset, byteLength);
    }
    const emails = extractRecordEmails(rec);
    for (let i = 0; i < emails.length; i++) {
      this.addToken(`em:${emails[i]}`, datasetId, byteOffset, byteLength);
    }
    const ips = extractRecordIps(rec);
    for (let i = 0; i < ips.length; i++) {
      this.addToken(`ip:${ips[i]}`, datasetId, byteOffset, byteLength);
    }
    const phones = extractRecordPhones(rec);
    for (let i = 0; i < phones.length; i++) {
      this.addToken(`ph:${phones[i]}`, datasetId, byteOffset, byteLength);
    }
    const usernames = extractRecordUsernames(rec);
    for (let i = 0; i < usernames.length; i++) {
      this.addToken(`un:${usernames[i]}`, datasetId, byteOffset, byteLength);
    }
    const extraIds = extractRecordExtraIdentifiers(rec);
    for (let i = 0; i < extraIds.length; i++) {
      this.addToken(`ex:${extraIds[i]}`, datasetId, byteOffset, byteLength);
    }
  }

  flush() {
    if (this.bufferedCount === 0) return;
    if (!fs.existsSync(this.indexDir)) {
      fs.mkdirSync(this.indexDir, { recursive: true });
    }
    for (let b = 0; b < NUM_BUCKETS; b++) {
      const lines = this.buckets[b];
      if (lines.length === 0) continue;
      const bucketPath = path.join(this.indexDir, `b_${b.toString(16).padStart(2, '0')}.tsv`);
      fs.appendFileSync(bucketPath, lines.join(''), 'utf8');
      this.buckets[b] = [];
    }
    this.bufferedCount = 0;
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

  createWriter(flushThreshold = 4096): DiskIndexWriter {
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
    const CHUNK_SIZE = 256 * 1024;
    const buf = Buffer.allocUnsafe(CHUNK_SIZE);
    const fd = fs.openSync(bucketPath, 'r');
    const decoder = new StringDecoder('utf8');
    let leftover = '';

    try {
      let bytesRead = 0;
      while ((bytesRead = fs.readSync(fd, buf, 0, CHUNK_SIZE, null)) > 0) {
        const text = leftover + decoder.write(buf.subarray(0, bytesRead));
        let start = 0;
        let nl = text.indexOf('\n', start);
        while (nl !== -1) {
          const line = text.slice(start, nl);
          start = nl + 1;
          for (let p = 0; p < prefixes.length; p++) {
            const prefix = prefixes[p];
            if (line.startsWith(prefix)) {
              this.parsePostingLine(line.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
              if (postings.length >= maxTotal) return postings;
              break;
            }
          }
          nl = text.indexOf('\n', start);
        }
        leftover = text.slice(start);
      }

      const tail = (leftover + decoder.end()).trim();
      if (tail) {
        for (let p = 0; p < prefixes.length; p++) {
          const prefix = prefixes[p];
          if (tail.startsWith(prefix)) {
            this.parsePostingLine(tail.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
            break;
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
    const CHUNK_SIZE = 256 * 1024;
    const buf = Buffer.allocUnsafe(CHUNK_SIZE);
    const decoder = new StringDecoder('utf8');
    let leftover = '';
    let filePos = 0;

    try {
      while (true) {
        const { bytesRead } = await handle.read(buf, 0, CHUNK_SIZE, filePos);
        if (bytesRead === 0) break;
        filePos += bytesRead;
        const text = leftover + decoder.write(buf.subarray(0, bytesRead));
        let start = 0;
        let nl = text.indexOf('\n', start);
        while (nl !== -1) {
          const line = text.slice(start, nl);
          start = nl + 1;
          for (let p = 0; p < prefixes.length; p++) {
            const prefix = prefixes[p];
            if (line.startsWith(prefix)) {
              this.parsePostingLine(line.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
              if (postings.length >= maxTotal) return postings;
              break;
            }
          }
          nl = text.indexOf('\n', start);
        }
        leftover = text.slice(start);
      }

      const tail = (leftover + decoder.end()).trim();
      if (tail) {
        for (let p = 0; p < prefixes.length; p++) {
          const prefix = prefixes[p];
          if (tail.startsWith(prefix)) {
            this.parsePostingLine(tail.slice(prefix.length), activeDatasetIds, seenOffsetKeys, postings);
            break;
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
  if (records.length === 0 && appendMode) return 0;
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
    const CHUNK = 2000;
    for (let i = 0; i < records.length; i += CHUNK) {
      const slice = records.slice(i, i + CHUNK);
      let block = '';
      for (let j = 0; j < slice.length; j++) {
        const line = `${JSON.stringify(slice[j])}\n`;
        const lineBytes = Buffer.byteLength(line, 'utf8');
        writer.indexRecord(slice[j], slice[j].datasetId, cursor, lineBytes);
        cursor += lineBytes;
        block += line;
      }
      totalWritten += Buffer.byteLength(block, 'utf8');
      fs.writeSync(fd, block, undefined, 'utf8');
    }
  } finally {
    fs.closeSync(fd);
    writer.flush();
  }
  return totalWritten;
}

export function iterateShardRecordsSync(
  shardPath: string,
  onRecord: (rec: IntelRecord) => boolean | void,
) {
  if (!fs.existsSync(shardPath)) return;
  const CHUNK_SIZE = 256 * 1024;
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
  const indexWriter = diskIndex.createWriter(4096);

  const tmpShardPath = `${shardPath}.ingest.tmp`;
  const shardDir = path.dirname(shardPath);
  if (!fs.existsSync(shardDir)) {
    fs.mkdirSync(shardDir, { recursive: true });
  }

  const outFd = fs.openSync(tmpShardPath, 'w', 0o600);
  let byteCursor = 0;
  let recordCount = 0;
  let pendingLinesBlock = '';
  let pendingLineCount = 0;
  let yieldCounter = 0;

  const flushShardBlock = () => {
    if (!pendingLinesBlock) return;
    fs.writeSync(outFd, pendingLinesBlock, undefined, 'utf8');
    pendingLinesBlock = '';
    pendingLineCount = 0;
  };

  const emitRecord = (row: Record<string, string>) => {
    const rec = normalizeSingleRow(row, mapping, datasetId, datasetName, recordCount, mappedFields);
    const jsonLine = `${JSON.stringify(rec)}\n`;
    const lineBytes = Buffer.byteLength(jsonLine, 'utf8');
    indexWriter.indexRecord(rec, datasetId, byteCursor, lineBytes);
    byteCursor += lineBytes;
    pendingLinesBlock += jsonLine;
    pendingLineCount += 1;
    recordCount += 1;
    yieldCounter += 1;

    if (pendingLineCount >= 1000) {
      flushShardBlock();
    }
    if (recordCount % 2500 === 0) {
      onProgress?.(recordCount, byteCursor);
    }
  };

  const maybeYield = async () => {
    if (yieldCounter >= 500) {
      yieldCounter = 0;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  };

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

    const READ_CHUNK = 256 * 1024;
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

        let segmentStart = 0;
        for (let i = 0; i < text.length; i++) {
          const ch = text[i];
          if (inStr) {
            if (escaped) escaped = false;
            else if (ch === '\\') escaped = true;
            else if (ch === '"') inStr = false;
            continue;
          }
          if (ch === '"') {
            inStr = true;
            continue;
          }
          if (ch === '{') {
            depth += 1;
            if (depth === targetDepth && !capturing) {
              capturing = true;
              segmentStart = i;
              objBuffer = '';
            }
          } else if (ch === '}') {
            if (capturing && depth === targetDepth) {
              objBuffer += text.slice(segmentStart, i + 1);
              capturing = false;
              try {
                const parsed = JSON.parse(objBuffer) as unknown;
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                  const flat = flattenObject(parsed as Record<string, unknown>);
                  for (const k of Object.keys(flat)) {
                    if (colSet.size < 50) colSet.add(k);
                  }
                  emitRecord(flat);
                }
              } catch {
                // Skip malformed JSON object
              }
              objBuffer = '';
              await maybeYield();
            }
            depth = Math.max(0, depth - 1);
          }
        }
        if (capturing) {
          objBuffer += text.slice(segmentStart);
          // Guard against corrupted unclosed giant token (>16 MB single object)
          if (objBuffer.length > 16 * 1024 * 1024) {
            capturing = false;
            objBuffer = '';
          }
        }
      }
      decoder.end();
    } else if (isSqlDump) {
      // Streaming SQL INSERT statement parser
      let sqlBuffer = '';
      let firstChunk = true;
      const headerRe = /INSERT\s+(?:IGNORE\s+)?INTO\s+[`"\[]?[\w.-]+[`"\]]?(?:\s*\(([^)]+)\))?\s+VALUES\s*/i;

      const processSqlStatement = async (stmt: string) => {
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
            rowObj[colName] = cleanInvisibleChars(tuple[idx] || '');
          }
          emitRecord(rowObj);
          await maybeYield();
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

        let semiIdx = sqlBuffer.indexOf(';');
        while (semiIdx !== -1) {
          const stmt = sqlBuffer.slice(0, semiIdx);
          sqlBuffer = sqlBuffer.slice(semiIdx + 1);
          await processSqlStatement(stmt);
          semiIdx = sqlBuffer.indexOf(';');
        }
      }
      sqlBuffer += decoder.end();
      if (sqlBuffer.trim()) {
        await processSqlStatement(sqlBuffer);
      }
    } else {
      // Streaming Line-by-Line Reader (CSV, TSV, Colon, ULP, NDJSON, Mixed Text, Logs)
      let leftover = '';
      let lineIndex = 0;
      let firstChunk = true;
      const baseColumns = opts.columns || [];

      const processLine = async (rawLine: string) => {
        const line = cleanInvisibleChars(rawLine);
        if (!line) return;
        const currentLineNo = lineIndex;
        lineIndex += 1;

        if (currentLineNo === 0 && hasHeader) {
          return;
        }

        if (format === 'ndjson' || (line.startsWith('{') && line.endsWith('}'))) {
          try {
            const obj = JSON.parse(line) as unknown;
            if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
              const flat = flattenObject(obj as Record<string, unknown>);
              for (const k of Object.keys(flat)) {
                if (colSet.size < 50) colSet.add(k);
              }
              emitRecord(flat);
              await maybeYield();
              return;
            }
          } catch {
            // Fall through to mixed-line parser
          }
        }

        if (isHeterogeneous) {
          const row = parseMixedSingleLine(line);
          emitRecord(row);
          await maybeYield();
          return;
        }

        const cells = parseCsvLine(line, delimiter);
        if (cells.every((c) => !c)) return;
        const rowObj: Record<string, string> = {};
        const colCount = Math.max(baseColumns.length, cells.length);
        for (let c = 0; c < colCount; c++) {
          const colName = baseColumns[c] || `sutun_${c + 1}`;
          if (colSet.size < 50) colSet.add(colName);
          rowObj[colName] = cells[c] ?? '';
        }
        emitRecord(rowObj);
        await maybeYield();
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

        let start = 0;
        let nl = text.indexOf('\n', start);
        while (nl !== -1) {
          let line = text.slice(start, nl);
          if (line.endsWith('\r')) line = line.slice(0, -1);
          start = nl + 1;
          await processLine(line);
          nl = text.indexOf('\n', start);
        }
        leftover = text.slice(start);
      }

      const tail = leftover + decoder.end();
      if (tail.trim()) {
        await processLine(tail);
      }
    }

    if (signal?.aborted) throw new Error('İçe aktarma iptal edildi.');
    flushShardBlock();
    indexWriter.flush();
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
    await handle.close().catch(() => {});
  }
}
