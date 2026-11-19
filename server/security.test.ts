import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createRateLimiter,
  generateThirtyDigitKey,
  getClientIp,
  hashAdminKey,
  hashPassword,
  isIpTemporarilyBlocked,
  isReservedUsername,
  isSensitiveHttpPath,
  recordIpViolation,
  sanitizeExtraObject,
  signSessionToken,
  verifyAdminKey,
  verifyAdminSessionClaim,
  verifyManagerSessionClaim,
  verifyPassword,
  verifySessionToken,
} from './security.ts';
import { checkDisposableEmail, isDomainInDisposableBlocklist } from './disposable.ts';
import { runEmailOsint } from './emailOsint.ts';
import { isValidIpAddress, runIpOsint } from './ipOsint.ts';
import { ServerStore } from './store.ts';
import { sanitizeRecordsForQueryResponse } from '../src/utils/search.ts';
import type { Request, Response } from 'express';

test('30-digit admin key generator and verifier enforce strict format and timing-safe match', () => {
  const key = generateThirtyDigitKey();
  assert.match(key, /^\d{30}$/);
  const hash = hashAdminKey(key);

  assert.equal(verifyAdminKey(key, hash), true);
  assert.equal(verifyAdminKey(key.slice(0, 29) + (key[29] === '0' ? '1' : '0'), hash), false);
  assert.equal(verifyAdminKey('12345', hash), false);
  assert.equal(verifyAdminKey('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', hash), false);
});

test('scrypt password hashing and HMAC session tokens with epoch verify cleanly', () => {
  const pwHash = hashPassword('GucluSifre!2026');
  assert.equal(verifyPassword('GucluSifre!2026', pwHash), true);
  assert.equal(verifyPassword('YanlisSifre', pwHash), false);

  const secret = 'test-secret-key';
  const token = signSessionToken({ userId: 'u1', role: 'Üye', exp: Date.now() + 60000, epoch: 'epoch_v1' }, secret);
  const verified = verifySessionToken(token, secret);
  assert.ok(verified);
  assert.equal(verified.userId, 'u1');
  assert.equal(verified.epoch, 'epoch_v1');
  assert.equal(verifySessionToken(token, 'wrong-secret'), null);

  const expired = signSessionToken({ userId: 'u1', role: 'Üye', exp: Date.now() - 1000, epoch: 'epoch_v1' }, secret);
  assert.equal(verifySessionToken(expired, secret), null);
});

test('IP intrusion shield auto-blocks repeated violations and ignores spoofed X-Forwarded-For', () => {
  const fakeReq = {
    ip: '203.0.113.55',
    headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.55' },
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as Request;
  assert.equal(getClientIp(fakeReq), '203.0.113.55');

  const cleanIp = '198.51.100.10';
  const attackerIp = '198.51.100.250';
  assert.equal(isIpTemporarilyBlocked(cleanIp).blocked, false);
  assert.equal(isIpTemporarilyBlocked(attackerIp).blocked, false);

  recordIpViolation(attackerIp, 3);
  assert.equal(isIpTemporarilyBlocked(attackerIp).blocked, false);
  recordIpViolation(attackerIp, 3);
  assert.equal(isIpTemporarilyBlocked(attackerIp).blocked, false);
  recordIpViolation(attackerIp, 2);
  const blocked = isIpTemporarilyBlocked(attackerIp);
  assert.equal(blocked.blocked, true);
  assert.ok(blocked.retryAfterSec > 0);
  assert.equal(isIpTemporarilyBlocked(cleanIp).blocked, false);
});

test('Reserved admin/system usernames are blocked from registration', () => {
  assert.equal(isReservedUsername('admin'), true);
  assert.equal(isReservedUsername('Admin_Root'), true);
  assert.equal(isReservedUsername('sistem_yoneticisi'), true);
  assert.equal(isReservedUsername('moderator'), true);
  assert.equal(isReservedUsername('sentarika_test'), true);
  assert.equal(isReservedUsername('ahmet_34'), false);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-test-'));
  try {
    const store = new ServerStore(tmpDir);
    assert.throws(
      () => store.registerUserDirect('normal@gmail.com', 'admin', 'GucluSifre!123', '127.0.0.1', 'uid_1'),
      /ayrılmıştır/,
    );
    assert.ok(!isReservedUsername(store.suggestUsername('admin@gmail.com', 'Admin')));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('sanitizeExtraObject strips prototype pollution keys', () => {
  const malicious = JSON.parse('{"__proto__":{"polluted":"yes"},"role":"Mod"}');
  const clean = sanitizeExtraObject(malicious);
  assert.equal(Object.prototype.hasOwnProperty.call(clean, '__proto__'), false);
  assert.equal(clean.role, 'Mod');
});

test('Temp-mail protection detects direct domains, subdomains, and reserved domains', async () => {
  assert.equal(isDomainInDisposableBlocklist('tempmail.plus'), true);
  assert.equal(isDomainInDisposableBlocklist('sub.mailinator.com'), true);
  assert.equal(isDomainInDisposableBlocklist('gmail.com'), false);

  const blocked = await checkDisposableEmail('bot@1secmail.org', { skipNetwork: true });
  assert.equal(blocked.isDisposable, true);
  assert.equal(blocked.detector, 'blocklist');

  const reserved = await checkDisposableEmail('fake@domain.test', { skipNetwork: true });
  assert.equal(reserved.isDisposable, true);
  assert.equal(reserved.detector, 'reserved-domain');

  const clean = await checkDisposableEmail('realuser@gmail.com', { skipNetwork: true });
  assert.equal(clean.isDisposable, false);
  assert.equal(clean.detector, 'clean');
});

test('ServerStore cloud snapshot preserves datasets cleanly, tracks tombstones, and skips deleted/duplicate IDs on restore', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-store-'));
  try {
    const store = new ServerStore(tmpDir);
    const snap = store.getCloudSnapshot();
    assert.ok(Array.isArray(snap.datasets));
    assert.ok(snap.roles.Üye);
    const res = store.restoreFromCloudSnapshot({
      datasets: snap.datasets.slice(0, 1),
      records: snap.records.slice(0, 1),
    });
    assert.equal(res.restoredDatasets, 0);
    assert.equal(res.restoredRecords, 0);

    const targetDs = {
      id: 'ds_tombstone_test',
      name: 'Tombstone Test',
      category: 'both' as const,
      format: 'synthetic' as const,
      recordCount: 1,
      columns: ['discordId'],
      mapping: { discordIdField: 'discordId', emailField: 'email', usernameField: 'username', sourceField: 'source', ipField: 'ip', phoneField: 'phone', notesField: 'notes' },
      importedAt: new Date().toISOString(),
      sizeBytes: 64,
    };
    const targetRec = {
      id: 'rec_tombstone_1',
      datasetId: 'ds_tombstone_test',
      datasetName: 'Tombstone Test',
      discordId: '123456789012345678',
      email: '',
      username: 'test_u',
      source: 'test',
      ip: '',
      phone: '',
      notes: '',
      extra: {},
    };
    store.addDataset(targetDs, [targetRec]);
    assert.equal(store.deleteDataset('ds_tombstone_test'), true);
    assert.ok(store.getCloudSnapshot().deletedDatasetIds.includes('ds_tombstone_test'));

    const blockedRestore = store.restoreFromCloudSnapshot({
      datasets: [targetDs],
      records: [targetRec],
    });
    assert.equal(blockedRestore.restoredDatasets, 0);
    assert.equal(blockedRestore.restoredRecords, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('verifyAdminSessionClaim rejects forged or non-root admin claims and accepts genuine admin grant', () => {
  const expectedEpoch = 'epoch_admin_abc';
  const validAdmin = {
    userId: 'admin_root',
    role: 'Admin',
    exp: Date.now() + 60_000,
    epoch: 'user_epoch_1',
    adminGrant: true,
    adminEpoch: expectedEpoch,
  };
  assert.equal(verifyAdminSessionClaim(validAdmin, expectedEpoch), true);

  assert.equal(verifyAdminSessionClaim(null, expectedEpoch), false);
  assert.equal(verifyAdminSessionClaim({ ...validAdmin, userId: 'usr_123' }, expectedEpoch), false);
  assert.equal(verifyAdminSessionClaim({ ...validAdmin, role: 'Üye' }, expectedEpoch), false);
  assert.equal(verifyAdminSessionClaim({ ...validAdmin, adminGrant: false }, expectedEpoch), false);
  assert.equal(verifyAdminSessionClaim({ ...validAdmin, adminEpoch: 'wrong_epoch' }, expectedEpoch), false);
});

test('isSensitiveHttpPath blocks sensitive directories, traversal, and config/key extensions', () => {
  assert.equal(isSensitiveHttpPath('/data/admin.key'), true);
  assert.equal(isSensitiveHttpPath('//data/secrets.json'), true);
  assert.equal(isSensitiveHttpPath('/./data/users.json'), true);
  assert.equal(isSensitiveHttpPath('/%64ata/admin.key'), true);
  assert.equal(isSensitiveHttpPath('/foo/../data/admin.key'), true);
  assert.equal(isSensitiveHttpPath('/server/store.ts'), true);
  assert.equal(isSensitiveHttpPath('/firestore.rules'), true);
  assert.equal(isSensitiveHttpPath('/firebase-blueprint.json'), true);
  assert.equal(isSensitiveHttpPath('/firebase-applet-config.json'), true);
  assert.equal(isSensitiveHttpPath('/package.json'), true);
  assert.equal(isSensitiveHttpPath('/Dockerfile'), true);
  assert.equal(isSensitiveHttpPath('/render.yaml'), true);
  assert.equal(isSensitiveHttpPath('/backup.sql'), true);
  assert.equal(isSensitiveHttpPath('/assets/index-123.js'), false);
  assert.equal(isSensitiveHttpPath('/api/auth/me'), false);
});

test('ServerStore supports post-upload dataset editing, record CRUD, re-normalization, and index invalidation', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-edit-'));
  try {
    const store = new ServerStore(tmpDir);
    const dsId = 'ds_edit_1';
    store.addDataset(
      {
        id: dsId,
        name: 'InitialFile',
        category: 'both',
        format: 'csv',
        recordCount: 1,
        columns: ['uid', 'mail'],
        mapping: {
          discordIdField: null,
          emailField: null,
          usernameField: null,
          sourceField: null,
          ipField: null,
          phoneField: null,
          notesField: null,
        },
        importedAt: new Date().toISOString(),
        sizeBytes: 120,
      },
      [
        {
          id: 'rec_1',
          datasetId: dsId,
          datasetName: 'InitialFile',
          discordId: '',
          email: '',
          username: 'init_u',
          source: 'LeakX',
          ip: '',
          phone: '',
          notes: '',
          extra: { uid: '104567890123456789', mail: 'edited@example.test' },
        },
      ],
    );

    const updated = store.updateDataset(dsId, {
      name: 'RenamedFile',
      mapping: {
        discordIdField: 'uid',
        emailField: 'mail',
        usernameField: null,
        sourceField: null,
        ipField: null,
        phoneField: null,
        notesField: null,
      },
      reNormalize: true,
    });
    assert.equal(updated.name, 'RenamedFile');
    assert.equal(store.getSearchIndex().byDiscordId.get('104567890123456789')?.length, 1);

    const added = store.addDatasetRecord(dsId, {
      discordId: '289104567890123456',
      email: 'added@example.test',
      username: 'manual_u',
      source: 'Manual',
      ip: '203.0.113.5',
      phone: '',
      notes: 'added manually',
      extra: {},
    });
    assert.equal(added.dataset.recordCount, 2);
    assert.equal(store.getSearchIndex().byDiscordId.get('289104567890123456')?.length, 1);

    store.updateDatasetRecord(dsId, added.record.id, { email: 'updated.added@example.test' });
    assert.equal(store.getSearchIndex().byEmail.get('updated.added@example.test')?.length, 1);

    const paged = store.getDatasetRecordsPaginated(dsId, 'updated.added@example.test', 1, 10);
    assert.equal(paged.total, 1);
    assert.equal(paged.records[0].datasetName, 'RenamedFile');

    const afterDel = store.deleteDatasetRecord(dsId, added.record.id);
    assert.equal(afterDel.recordCount, 1);
    assert.equal(store.getSearchIndex().byEmail.get('updated.added@example.test'), undefined);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Permanent Admin Key and session secret survive fresh cold starts and support NDJSON batch append', () => {
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-cold-a-'));
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-cold-b-'));
  try {
    const storeA = new ServerStore(dirA);
    const storeB = new ServerStore(dirB);
    assert.equal(storeA.getAdminKeyHash(), storeB.getAdminKeyHash());
    assert.equal(storeA.getSessionSecret(), storeB.getSessionSecret());

    // Signed token issued by container A verifies on fresh container B
    const token = signSessionToken(
      {
        userId: 'admin_root',
        role: 'Admin',
        adminGrant: true,
        adminEpoch: storeA.getAdminTokenEpoch(),
        exp: Date.now() + 60_000,
      },
      storeA.getSessionSecret(),
    );
    const verified = verifySessionToken(token, storeB.getSessionSecret());
    assert.ok(verified);
    assert.equal(verifyAdminSessionClaim(verified, storeB.getAdminTokenEpoch()), true);

    // Per-dataset NDJSON shard + batch append survives restart cleanly
    storeA.addDataset(
      {
        id: 'ds_shard_1',
        name: 'ShardOne',
        category: 'both',
        format: 'text',
        recordCount: 1,
        columns: ['discordId'],
        mapping: {
          discordIdField: 'discordId',
          emailField: null,
          usernameField: null,
          sourceField: null,
          ipField: null,
          phoneField: null,
          notesField: null,
        },
        importedAt: new Date().toISOString(),
        sizeBytes: 0,
      },
      [
        {
          id: 'ds_shard_1_0',
          datasetId: 'ds_shard_1',
          datasetName: 'ShardOne',
          discordId: '104567890123456789',
          email: '',
          username: 'shard_a',
          source: 'LeakA',
          ip: '',
          phone: '',
          notes: '',
          extra: {},
        },
      ],
    );
    storeA.appendDatasetBatch('ds_shard_1', [
      {
        id: 'ds_shard_1_1',
        datasetId: 'ds_shard_1',
        datasetName: 'ShardOne',
        discordId: '289104567890123456',
        email: 'shard.b@example.test',
        username: 'shard_b',
        source: 'LeakB',
        ip: '',
        phone: '',
        notes: '',
        extra: {},
      },
    ]);

    const reloadedStore = new ServerStore(dirA);
    assert.equal(reloadedStore.getStats().totalRecords, 2);
    assert.equal(reloadedStore.getDatasetById('ds_shard_1')?.recordCount, 2);
    assert.equal(reloadedStore.getSearchIndex().byEmail.get('shard.b@example.test')?.length, 1);
    assert.equal(reloadedStore.getAdminPublicProfile().email, '');
    assert.ok(reloadedStore.getTotalDataBytes() > 0);
  } finally {
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  }
});

test('ServerStore query blacklist blocks Discord IDs & emails, persists across restarts, and preserves in cloud snapshot', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-blacklist-'));
  try {
    const store = new ServerStore(tmpDir);
    const added = store.addBlacklistEntries('104567890123456789\nProtected@Example.Test, invalid_token');
    assert.equal(added.addedIds, 1);
    assert.equal(added.addedEmails, 1);
    assert.deepEqual(added.ignored, ['invalid_token']);

    assert.equal(store.isDiscordIdBlacklisted('104567890123456789'), true);
    assert.equal(store.isEmailBlacklisted('protected@example.test'), true);
    assert.equal(store.isDiscordIdBlacklisted('289104567890123456'), false);
    assert.equal(
      store.isRecordBlacklisted({
        id: 'r1',
        datasetId: 'ds1',
        datasetName: 'DS',
        discordId: '',
        email: '',
        username: 'user',
        source: 'Src',
        ip: '',
        phone: '',
        notes: 'linked to <@!104567890123456789>',
        extra: {},
      }),
      true,
    );

    const snapshot = store.getCloudSnapshot();
    assert.deepEqual(snapshot.blacklist.discordIds, ['104567890123456789']);
    assert.deepEqual(snapshot.blacklist.emails, ['protected@example.test']);

    const reloaded = new ServerStore(tmpDir);
    assert.equal(reloaded.isDiscordIdBlacklisted('104567890123456789'), true);
    assert.equal(reloaded.isEmailBlacklisted('protected@example.test'), true);

    reloaded.removeBlacklistEntry('discord_id', '104567890123456789');
    assert.equal(reloaded.isDiscordIdBlacklisted('104567890123456789'), false);
    assert.equal(reloaded.isEmailBlacklisted('protected@example.test'), true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Raw chunked upload + background DiskIndex analysis correlates across memory and disk datasets', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-disk-idx-'));
  try {
    const store = new ServerStore(tmpDir);

    // 1. In-memory dataset linking Discord ID -> shared email
    store.addDataset(
      {
        id: 'ds_mem_link',
        name: 'MemForum',
        category: 'both',
        format: 'text',
        recordCount: 1,
        columns: ['discordId', 'email'],
        mapping: {
          discordIdField: 'discordId',
          emailField: 'email',
          usernameField: null,
          sourceField: null,
          ipField: null,
          phoneField: null,
          notesField: null,
        },
        importedAt: new Date().toISOString(),
        sizeBytes: 120,
      },
      [
        {
          id: 'mem_0',
          datasetId: 'ds_mem_link',
          datasetName: 'MemForum',
          discordId: '104567890123456789',
          email: 'bridge.target@example.test',
          username: 'kuzey_mem',
          source: 'MemForum',
          ip: '198.51.100.11',
          phone: '',
          notes: '',
          extra: {},
        },
      ],
    );

    // 2. Raw chunked upload of ULP file into disk-backed dataset
    const rawUlpContent = [
      'https://secretline.top/login:bridge.target@example.test:UltraSecretPass!|hwid=HWID-DISK-42',
      'http://shop.demo.invalid:unrelated.disk@example.test:OtherPass99',
    ].join('\n');
    const rawBuf = Buffer.from(rawUlpContent, 'utf8');
    const splitAt = Math.floor(rawBuf.length / 2);

    const diskMeta = store.initRawUploadDataset({
      id: 'ds_disk_ulp',
      name: '[ULP]_Secretline_Disk',
      format: 'text',
      sizeBytes: rawBuf.length,
      columns: ['url', 'email', 'password', 'notes'],
      mapping: {
        discordIdField: null,
        emailField: null,
        usernameField: null,
        sourceField: null,
        ipField: null,
        phoneField: null,
        notesField: null,
      },
    });
    assert.equal(diskMeta.storageMode, 'disk');
    assert.equal(diskMeta.ingestionStatus, 'uploading');

    // Write chunks with idempotent byte offsets (including duplicate retry of chunk 1)
    store.appendRawUploadChunk('ds_disk_ulp', rawBuf.subarray(0, splitAt), 0);
    store.appendRawUploadChunk('ds_disk_ulp', rawBuf.subarray(0, splitAt), 0);
    store.appendRawUploadChunk('ds_disk_ulp', rawBuf.subarray(splitAt), splitAt);

    store.startBackgroundIngestion('ds_disk_ulp', {
      delimiter: ':',
      hasHeader: false,
      isHeterogeneous: true,
    });

    // Wait for async worker completion
    for (let i = 0; i < 60; i++) {
      const cur = store.getDatasetById('ds_disk_ulp');
      if (cur && (cur.ingestionStatus === 'ready' || cur.ingestionStatus === 'error')) {
        break;
      }
      await new Promise((r) => setTimeout(r, 25));
    }

    const finished = store.getDatasetById('ds_disk_ulp');
    assert.ok(finished);
    assert.equal(finished.ingestionStatus, 'ready');
    assert.equal(finished.recordCount, 2);
    assert.equal(store.getStats().totalRecords, 3);

    // Querying Discord ID finds memory primary match AND correlates into disk ULP record via bridge email!
    const crossRes = store.searchAcrossAllStores('104567890123456789', 'discord_id', true);
    assert.equal(crossRes.primaryMatches.length, 1);
    assert.equal(crossRes.relatedMatches.length, 1);
    assert.equal(crossRes.relatedMatches[0].datasetId, 'ds_disk_ulp');
    assert.equal(crossRes.relatedMatches[0].email, 'bridge.target@example.test');
    assert.equal(crossRes.scanMetrics?.scannedRecords, 3);

    // Bulk lookup across both stores also correlates
    const bulkRes = store.runBulkLookupAcrossAllStores(['104567890123456789']);
    assert.equal(bulkRes[0].matches.length, 2);

    // Pagination & database filtering across disk datasets work cleanly
    const paged = store.getDatasetRecordsPaginated('ds_disk_ulp', 'bridge.target@example.test', 1, 10);
    assert.equal(paged.total, 1);
    assert.equal(paged.records[0].email, 'bridge.target@example.test');

    // Persisted reload still resolves disk dataset queries cleanly
    const reloaded = new ServerStore(tmpDir);
    const reloadedSearch = reloaded.searchAcrossAllStores('104567890123456789', 'discord_id', true);
    assert.equal(reloadedSearch.primaryMatches.length, 1);
    assert.equal(reloadedSearch.relatedMatches.length, 1);

    // Deletion cleans up disk dataset
    assert.equal(reloaded.deleteDataset('ds_disk_ulp'), true);
    assert.equal(reloaded.getDatasetById('ds_disk_ulp'), null);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Async scrypt auth, shared-IP per-user rate limiter, parallel disk queries, and debounced flush hold up concurrently', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-conc-'));
  try {
    const store = new ServerStore(tmpDir);

    // 1. Concurrent async registrations + logins
    const users = await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        store.registerUserDirectAsync(
          `conc${i}@gmail.com`,
          `conc_user_${i}`,
          'StrongPass!2026',
          '198.51.100.77',
          `uid_conc_${i}`,
        ),
      ),
    );
    assert.equal(users.length, 6);

    const authResults = await Promise.all(
      users.map((u) => store.authenticateUserAsync(u.username, 'StrongPass!2026', '198.51.100.77')),
    );
    assert.equal(authResults.every((r) => Boolean(r?.user?.id)), true);

    // 2. Shared NAT IP with violationWeight: 0 + keyGenerator isolates users and never bans shared IP
    const sharedNatIp = '198.51.100.99';
    const userScopedLimiter = createRateLimiter({
      windowMs: 60_000,
      maxRequests: 2,
      keyPrefix: 'conc-test',
      violationWeight: 0,
      keyGenerator: (req) => String((req.headers['x-test-user'] as string) || getClientIp(req)),
    });

    const invokeLimiter = (userKey: string): Promise<number> =>
      new Promise((resolve) => {
        let status = 200;
        const req = {
          ip: sharedNatIp,
          headers: { 'x-test-user': userKey },
          socket: { remoteAddress: sharedNatIp },
        } as unknown as Request;
        const res = {
          setHeader() {},
          status(code: number) {
            status = code;
            return this;
          },
          json() {
            resolve(status);
            return this;
          },
        } as unknown as Response;
        userScopedLimiter(req, res, () => resolve(200));
      });

    assert.equal(await invokeLimiter('userA'), 200);
    assert.equal(await invokeLimiter('userA'), 200);
    assert.equal(await invokeLimiter('userA'), 429);
    assert.equal(await invokeLimiter('userB'), 200);
    assert.equal(isIpTemporarilyBlocked(sharedNatIp).blocked, false);

    // 3. Seed disk dataset and run 15 parallel async lookups + quota writes + flush
    const rawBuf = Buffer.from(
      '104567890123456789:target.conc@example.test:conc_target\n289104567890123456:other.conc@example.test:conc_other\n',
      'utf8',
    );
    store.initRawUploadDataset({
      id: 'ds_conc_disk',
      name: 'ConcDisk',
      format: 'text',
      sizeBytes: rawBuf.length,
      columns: ['discordId', 'email', 'username'],
      mapping: {
        discordIdField: 'discordId',
        emailField: 'email',
        usernameField: 'username',
        sourceField: null,
        ipField: null,
        phoneField: null,
        notesField: null,
      },
    });
    store.appendRawUploadChunk('ds_conc_disk', rawBuf, 0);
    store.startBackgroundIngestion('ds_conc_disk', { delimiter: ':', hasHeader: false, isHeterogeneous: false });

    for (let i = 0; i < 60; i++) {
      const cur = store.getDatasetById('ds_conc_disk');
      if (cur?.ingestionStatus === 'ready') break;
      await new Promise((r) => setTimeout(r, 20));
    }

    const searches = await Promise.all(
      Array.from({ length: 15 }, (_, idx) => {
        store.consumeQueryQuota(users[idx % users.length].id);
        store.appendQueryAuditLog({
          userId: users[idx % users.length].id,
          username: users[idx % users.length].username,
          queryType: 'id_lookup',
          target: '104567890123456789',
          matchCount: 1,
          ip: sharedNatIp,
        });
        return store.searchAcrossAllStoresAsync('104567890123456789', 'discord_id', true);
      }),
    );

    assert.equal(searches.every((s) => s.primaryMatches.length === 1), true);
    await store.flushPendingWrites();

    const reloaded = new ServerStore(tmpDir);
    assert.equal(reloaded.getUsersCount(), 6);
    assert.equal(reloaded.getQueryAuditLogs().length, 15);
    assert.equal(
      reloaded.listAllUsersForAdmin().reduce((acc, u) => acc + u.dailyUsed, 0),
      15,
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Hybrid memory+disk search blocks CDN/weak IP cross-ID leaks and sanitizeRecordsForQueryResponse hides dataset origin & cleans legacy timestamp phones', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-hybrid-iso-'));
  try {
    const store = new ServerStore(tmpDir);

    // 1. Seed in-memory dataset with target Discord ID + Cloudflare IP + legacy timestamp inside phone
    store.addDataset(
      {
        id: 'ds_mem_part',
        name: 'data_part2',
        category: 'both',
        format: 'csv',
        recordCount: 2,
        columns: ['discordId', 'username', 'ip', 'phone', 'source'],
        mapping: {
          discordIdField: 'discordId',
          emailField: null,
          usernameField: 'username',
          sourceField: 'source',
          ipField: 'ip',
          phoneField: 'phone',
          notesField: null,
        },
        importedAt: new Date().toISOString(),
        sizeBytes: 256,
      },
      [
        {
          id: 'mem_target_1',
          datasetId: 'ds_mem_part',
          datasetName: 'data_part2',
          discordId: '701810803321471176',
          email: '',
          username: '53775969',
          source: 'data-2',
          ip: '172.70.51.219',
          phone: '2025-07-26 19:17:38',
          notes: '',
          extra: {},
        },
        {
          id: 'mem_foreign_cf',
          datasetId: 'ds_mem_part',
          datasetName: 'data_part2',
          discordId: '289104567890123456',
          email: 'stranger.cf@example.test',
          username: 'ff0',
          source: 'data_part2.csv',
          ip: '172.70.51.219',
          phone: '2025-07-26 19:17:38',
          notes: '',
          extra: {},
        },
      ],
    );

    // 2. Seed disk-backed dataset containing a foreign Discord ID on same CF IP AND an unattributed email-linked record
    const rawDisk = [
      '999888777666555444:foreign.disk@example.test:ff0:172.70.51.219',
      '701810803321471176:real.owner@example.test:owner_nick:198.51.100.88',
      '05551112233:real.owner@example.test:shop_buyer:203.0.113.12',
    ].join('\n');
    const diskBuf = Buffer.from(rawDisk, 'utf8');
    store.initRawUploadDataset({
      id: 'ds_disk_part',
      name: 'legacymedya&yunusbey id data',
      format: 'text',
      sizeBytes: diskBuf.length,
      columns: ['id', 'email', 'username', 'ip'],
      mapping: {
        discordIdField: null,
        emailField: null,
        usernameField: null,
        sourceField: null,
        ipField: null,
        phoneField: null,
        notesField: null,
      },
    });
    store.appendRawUploadChunk('ds_disk_part', diskBuf, 0);
    store.startBackgroundIngestion('ds_disk_part', { delimiter: ':', hasHeader: false, isHeterogeneous: true });

    for (let i = 0; i < 60; i++) {
      const cur = store.getDatasetById('ds_disk_part');
      if (cur?.ingestionStatus === 'ready') break;
      await new Promise((r) => setTimeout(r, 20));
    }

    const res = await store.searchAcrossAllStoresAsync('701810803321471176', 'discord_id', true);
    const allMatched = [...res.primaryMatches, ...res.relatedMatches];

    // No foreign Discord ID leaked via Cloudflare IP (172.70.51.219), timestamp phone, or hex username "ff0"
    assert.equal(allMatched.some((r) => r.discordId && r.discordId !== '701810803321471176'), false);
    assert.equal(res.primaryMatches.length, 2);
    assert.equal(res.relatedMatches.length, 1);
    assert.equal(res.relatedMatches[0].email, 'real.owner@example.test');

    // sanitizeRecordsForQueryResponse strips datasetId, datasetName, filename-like sources (data-2 / data_part2.csv), and moves timestamp phone -> extra.tarih
    const sanitized = sanitizeRecordsForQueryResponse(allMatched);
    for (const r of sanitized) {
      assert.equal(r.datasetId, '');
      assert.equal(r.datasetName, '');
      assert.equal(r.source, '');
    }
    const memTargetSanitized = sanitized.find((r) => r.id === 'mem_target_1');
    assert.ok(memTargetSanitized);
    assert.equal(memTargetSanitized.phone, '');
    assert.equal(memTargetSanitized.extra.tarih, '2025-07-26 19:17:38');
    const genuinePhoneRec = sanitized.find((r) => r.discordId === '');
    assert.ok(genuinePhoneRec);
    assert.equal(genuinePhoneRec.phone, '05551112233');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Two-tier Admin vs Manager (Yönetici Key): Admins leave zero trace in queryLogs, Manager inspects & bans Admin IPs and rotates Admin key', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-manager-'));
  try {
    // Seed legacy query_logs.json containing an exposed Sistem Yöneticisi entry + IP
    const legacyLogs = [
      {
        id: 'q_legacy_admin',
        userId: 'admin_root',
        username: 'Sistem Yöneticisi',
        queryType: 'id_lookup',
        target: '701810803321471176',
        matchCount: 5,
        ip: '203.0.113.200',
        timestamp: new Date().toISOString(),
      },
      {
        id: 'q_member_1',
        userId: 'usr_normal_1',
        username: 'ali_member',
        queryType: 'id_lookup',
        target: '104567890123456789',
        matchCount: 1,
        ip: '198.51.100.44',
        timestamp: new Date().toISOString(),
      },
    ];
    fs.writeFileSync(path.join(tmpDir, 'query_logs.json'), JSON.stringify(legacyLogs, null, 2), 'utf8');

    const store = new ServerStore(tmpDir);

    // 1. Legacy Sistem Yöneticisi log + IP was purged on startup, while normal user log remains
    const logs = store.getQueryAuditLogs();
    assert.equal(logs.length, 1);
    assert.equal(logs[0].username, 'ali_member');

    // 2. Appending new admin_root / manager_root / Sistem Yöneticisi audit entries is silently ignored
    store.appendQueryAuditLog({
      userId: 'admin_root',
      username: 'Sistem Yöneticisi',
      queryType: 'id_lookup',
      target: '123',
      matchCount: 0,
      ip: '198.51.100.9',
    });
    store.appendQueryAuditLog({
      userId: 'manager_root',
      username: 'Yönetici',
      queryType: 'email_osint',
      target: 'a@b.com',
      matchCount: 0,
      ip: '198.51.100.1',
    });
    assert.equal(store.getQueryAuditLogs().length, 1);

    // 3. Existing admin key hash and separate manager key hash both initialize cleanly
    const initialAdminHash = store.getAdminKeyHash();
    const managerHash = store.getManagerKeyHash();
    assert.match(initialAdminHash, /^[0-9a-f]{64}$/);
    assert.match(managerHash, /^[0-9a-f]{64}$/);
    assert.notEqual(initialAdminHash, managerHash);

    // 4. Manager claim verifier strictly separates manager_root from admin_root
    const mEpoch = store.getManagerTokenEpoch();
    assert.equal(
      verifyManagerSessionClaim(
        { userId: 'manager_root', role: 'Admin', exp: Date.now() + 60_000, managerGrant: true, managerEpoch: mEpoch },
        mEpoch,
      ),
      true,
    );
    assert.equal(
      verifyManagerSessionClaim(
        {
          userId: 'admin_root',
          role: 'Admin',
          exp: Date.now() + 60_000,
          adminGrant: true,
          adminEpoch: store.getAdminTokenEpoch(),
        },
        mEpoch,
      ),
      false,
    );

    // 5. Tracking Admin IPs works for Manager oversight ONLY, and Admin IP ban revokes token epoch
    store.recordAdminIpActivity('203.0.113.77', 'login');
    store.recordAdminIpActivity('203.0.113.77', 'query');
    assert.equal(store.listAllUsersForAdmin().some((u) => u.id === 'admin_root' || u.id === 'manager_root'), false);

    const oldEpoch = store.getAdminTokenEpoch();
    const afterIpBan = store.setAdminIpBan('203.0.113.77', true, 'Yetkisiz IP');
    assert.equal(afterIpBan.trackedIps.find((r) => r.ip === '203.0.113.77')?.banned, true);
    assert.equal(afterIpBan.trackedIps.find((r) => r.ip === '203.0.113.77')?.queryCount, 1);
    assert.equal(store.isAdminBlockedForIp('203.0.113.77').blocked, true);
    assert.equal(store.isAdminBlockedForIp('203.0.113.78').blocked, false);
    assert.notEqual(store.getAdminTokenEpoch(), oldEpoch);

    store.setAdminIpBan('203.0.113.77', false);
    assert.equal(store.isAdminBlockedForIp('203.0.113.77').blocked, false);

    // 6. Global Admin ban blocks every IP
    store.setAdminGlobalBan(true, 'Bakım');
    assert.equal(store.isAdminBlockedForIp('203.0.113.78').blocked, true);
    store.setAdminGlobalBan(false);
    assert.equal(store.isAdminBlockedForIp('203.0.113.78').blocked, false);

    // 7. Auto-reset Admin Key generates valid 30-digit CSPRNG key, updates hash + epoch, and persists across restart
    const epochBeforeReset = store.getAdminTokenEpoch();
    const rotated = store.resetOrUploadAdminKey();
    assert.match(rotated.adminKey, /^\d{30}$/);
    assert.equal(verifyAdminKey(rotated.adminKey, store.getAdminKeyHash()), true);
    assert.notEqual(store.getAdminKeyHash(), initialAdminHash);
    assert.notEqual(store.getAdminTokenEpoch(), epochBeforeReset);

    const reloaded = new ServerStore(tmpDir);
    assert.equal(reloaded.getAdminKeyHash(), store.getAdminKeyHash());
    assert.equal(verifyAdminKey(rotated.adminKey, reloaded.getAdminKeyHash()), true);

    // 8. Root Manager has full Admin permissions, unlimited query quota, and rate-limiter skip bypass
    const managerProfile = reloaded.getManagerPublicProfile();
    assert.equal(managerProfile.role, 'Admin');
    assert.equal(managerProfile.isRootManager, true);
    assert.equal(managerProfile.permissions.canIdLookup, true);
    assert.equal(managerProfile.permissions.canBulkLookup, true);
    assert.equal(managerProfile.permissions.canEmailOsint, true);
    for (let i = 0; i < 10; i++) {
      assert.equal(reloaded.consumeQueryQuota('manager_root').allowed, true);
      assert.equal(reloaded.consumeQueryQuota('admin_root').allowed, true);
    }

    let skippedCalls = 0;
    const exemptLimiter = createRateLimiter({
      windowMs: 60_000,
      maxRequests: 1,
      keyPrefix: 'exempt-test',
      skip: (r) => r.headers['x-priv'] === '1',
    });
    for (let i = 0; i < 5; i++) {
      exemptLimiter(
        { ip: '198.51.100.123', headers: { 'x-priv': '1' }, socket: { remoteAddress: '198.51.100.123' } } as unknown as Request,
        { setHeader() {}, status() { return this; }, json() { return this; } } as unknown as Response,
        () => { skippedCalls += 1; },
      );
    }
    assert.equal(skippedCalls, 5);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Email OSINT normalizes canonical aliases and aggregates local exposed signals into identitySummary', async () => {
  const sampleRecords = [
    {
      id: 'osint_rec_1',
      datasetId: 'ds_osint_test',
      datasetName: 'OsintTest',
      discordId: '104567890123456789',
      email: 'alice.osint@example.test',
      username: 'alice_nick',
      source: 'TestArchive',
      ip: '198.51.100.22',
      phone: '+905550001122',
      notes: '',
      extra: {
        password: 'SampleExposedValue99',
        token: 'tok_sample_1234567890',
        hwid: 'HWID-TEST-77',
      },
    },
  ];

  const report = await runEmailOsint('Alice.Osint+tag@example.test', sampleRecords, 'tr');
  assert.equal(report.isValidSyntax, true);
  assert.ok(report.identitySummary);
  assert.equal(report.identitySummary.canonicalEmail, 'alice.osint@example.test');
  assert.equal(report.localMatches.length, 1);
  assert.ok(report.identitySummary.discoveredUsernames.includes('alice_nick'));
  assert.ok(report.identitySummary.localExposedSignals.passwords.includes('SampleExposedValue99'));
  assert.ok(report.identitySummary.localExposedSignals.tokens.includes('tok_sample_1234567890'));
  assert.ok(report.identitySummary.localExposedSignals.hwids.includes('HWID-TEST-77'));
  assert.ok(report.identitySummary.localExposedSignals.ips.includes('198.51.100.22'));
  assert.ok(report.identitySummary.localExposedSignals.discordIds.includes('104567890123456789'));
});

test('Full vault snapshot exports both memory and ready disk datasets and restores them queryable end-to-end', async () => {
  const dirSrc = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-vault-src-'));
  const dirDst = fs.mkdtempSync(path.join(os.tmpdir(), 'sentarika-vault-dst-'));
  try {
    const src = new ServerStore(dirSrc);
    src.addBlacklistEntries('999888777666555444');
    src.updateRoleConfig('Destekçi', { dailyQueryLimit: 555 });
    await src.registerUserDirectAsync('member.vault@gmail.com', 'vault_user', 'VaultPass!2026', '198.51.100.9', 'uid_v_1');

    // Disk-backed dataset via raw upload
    const rawDisk = '701810803321471176:vault.disk@example.test:disk_owner:198.51.100.55\n';
    const buf = Buffer.from(rawDisk, 'utf8');
    src.initRawUploadDataset({
      id: 'ds_vault_disk',
      name: 'VaultDiskDs',
      format: 'text',
      sizeBytes: buf.length,
      columns: ['id', 'email', 'username', 'ip'],
      mapping: {
        discordIdField: null,
        emailField: null,
        usernameField: null,
        sourceField: null,
        ipField: null,
        phoneField: null,
        notesField: null,
      },
    });
    src.appendRawUploadChunk('ds_vault_disk', buf, 0);
    src.startBackgroundIngestion('ds_vault_disk', { delimiter: ':', hasHeader: false, isHeterogeneous: true });
    for (let i = 0; i < 60; i++) {
      const cur = src.getDatasetById('ds_vault_disk');
      if (cur?.ingestionStatus === 'ready') break;
      await new Promise((r) => setTimeout(r, 20));
    }

    const snap = src.getCloudSnapshot();
    assert.equal(snap.datasets.some((d) => d.id === 'ds_vault_disk'), true);
    assert.equal(snap.records.some((r) => r.datasetId === 'ds_vault_disk' && r.discordId === '701810803321471176'), true);
    assert.equal(snap.blacklist.discordIds.includes('999888777666555444'), true);

    const dst = new ServerStore(dirDst);
    const restored = dst.restoreFromCloudSnapshot(snap);
    assert.equal(restored.restoredUsers, 1);
    assert.equal(restored.restoredDatasets, 1);
    assert.equal(restored.restoredRecords, 1);
    assert.equal(dst.getRoleConfigs().Destekçi.dailyQueryLimit, 555);
    assert.equal(dst.isDiscordIdBlacklisted('999888777666555444'), true);

    const found = await dst.searchAcrossAllStoresAsync('701810803321471176', 'discord_id', true);
    assert.equal(found.primaryMatches.length, 1);
    assert.equal(found.primaryMatches[0].email, 'vault.disk@example.test');
  } finally {
    fs.rmSync(dirSrc, { recursive: true, force: true });
    fs.rmSync(dirDst, { recursive: true, force: true });
  }
});

test('Zero-dataset Legal IP OSINT validates IPv4/IPv6, isolates private/reserved ranges, and builds public report cleanly', async () => {
  assert.equal(isValidIpAddress('not-an-ip').valid, false);
  assert.equal(isValidIpAddress('999.999.1.1').valid, false);

  const normalizedPort = isValidIpAddress('1.1.1.1:443');
  assert.equal(normalizedPort.valid, true);
  assert.equal(normalizedPort.ip, '1.1.1.1');
  assert.equal(normalizedPort.version, 4);

  const normalizedV6 = isValidIpAddress('[2606:4700:4700::1111]');
  assert.equal(normalizedV6.valid, true);
  assert.equal(normalizedV6.ip, '2606:4700:4700::1111');
  assert.equal(normalizedV6.version, 6);

  const invalidReport = await runIpOsint('invalid-ip', 'tr', { skipNetwork: true });
  assert.equal(invalidReport.isValid, false);

  const lanReport = await runIpOsint('192.168.1.25', 'tr', { skipNetwork: true });
  assert.equal(lanReport.isValid, true);
  assert.equal(lanReport.isPublic, false);
  assert.match(lanReport.scopeNote, /RFC 1918/);
  assert.equal(lanReport.pivotLinks.length, 0);

  const cgnatReport = await runIpOsint('100.64.10.2', 'en', { skipNetwork: true });
  assert.equal(cgnatReport.isValid, true);
  assert.equal(cgnatReport.isPublic, false);
  assert.match(cgnatReport.scopeNote, /CGNAT/);

  const loopbackV6 = await runIpOsint('::1', 'tr', { skipNetwork: true });
  assert.equal(loopbackV6.isValid, true);
  assert.equal(loopbackV6.version, 6);
  assert.equal(loopbackV6.isPublic, false);

  const publicReport = await runIpOsint('1.1.1.1', 'tr', { skipNetwork: true });
  assert.equal(publicReport.isValid, true);
  assert.equal(publicReport.isPublic, true);
  assert.equal(publicReport.version, 4);
  assert.ok(publicReport.pivotLinks.some((l) => l.label === 'RIPEstat'));
  assert.ok(publicReport.pivotLinks.some((l) => l.label === 'Shodan'));
});
