import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
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
  verifyPassword,
  verifySessionToken,
} from './security.ts';
import { checkDisposableEmail, isDomainInDisposableBlocklist } from './disposable.ts';
import { ServerStore } from './store.ts';
import type { Request } from 'express';

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



