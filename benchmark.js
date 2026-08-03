/* eslint-env es2020 */
'use strict';

/**
 * benchmark.js — Production Benchmark Suite
 * Uses Node.js perf_hooks for high-precision measurement.
 */

const { performance } = require('perf_hooks');
const uid = require('./index');

const ITERATIONS = 100_000;
const COL1 = 35;
const COL2 = 15;
const COL3 = 12;
const COL4 = 12;

function bench(label, fn, iterations = ITERATIONS) {
  // Warmup
  for (let i = 0; i < 500; i++) fn();

  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const end = performance.now();

  const totalMs = end - start;
  const opsPerSec = Math.floor(iterations / (totalMs / 1000));
  const nsPerOp = (totalMs * 1_000_000) / iterations;

  return { label, totalMs, opsPerSec, nsPerOp, iterations };
}

function header(title) {
  const line = '═'.repeat(COL1 + COL2 + COL3 + COL4 + 4);
  console.log(`\n${line}`);
  console.log(`  ${title.toUpperCase()}`);
  console.log(`${line}`);
  console.log(
    '  ' +
    'Generator'.padEnd(COL1) +
    'ops/sec'.padStart(COL2) +
    'ns/op'.padStart(COL3) +
    'ms total'.padStart(COL4)
  );
  console.log('─'.repeat(COL1 + COL2 + COL3 + COL4 + 4));
}

function row(r) {
  console.log(
    '  ' +
    r.label.padEnd(COL1) +
    r.opsPerSec.toLocaleString().padStart(COL2) +
    r.nsPerOp.toFixed(2).padStart(COL3) +
    r.totalMs.toFixed(2).padStart(COL4)
  );
}

// ── Run Benchmarks ────────────────────────────────────────────────────────────

console.log('\n🚀 UUID-LAB PRODUCTION BENCHMARK');
console.log(`   Iterations: ${ITERATIONS.toLocaleString()}`);
console.log(`   Node.js:    ${process.version}`);
console.log(`   OS:         ${process.platform} ${process.arch}`);

header('Core ID Generation');
[
  bench('uuid (crypto.randomUUID)',    () => uid.uuid()),
  bench('uuidV4 (manual)',             () => uid.uuidV4()),
  bench('uuidV7',                      () => uid.uuidV7()),
  bench('nanoId (21 chars)',           () => uid.nanoId()),
  bench('nanoId (10 chars)',           () => uid.nanoId({ size: 10 })),
  bench('ulid',                        () => uid.ulid()),
  bench('ksuid',                       () => uid.ksuid()),
  bench('snowflakeId',                 () => uid.snowflakeId()),
].forEach(row);

header('Developer Experience');
[
  bench('typedId (user_...)',          () => uid.typedId('user')),
  bench('humanId',                     () => uid.humanId()),
  bench('sequentialId (padded)',       () => uid.sequentialId({ pad: 12 })),
  bench('prefixedId (custom)',         () => uid.prefixedId({ prefix: 'id' })),
  bench('shortId',                     () => uid.shortId()),
].forEach(row);

header('Security & Advanced');
[
  bench('signId + HMAC',               () => uid.signId('test', 'secret')),
  bench('verifySignedId',              () => uid.verifySignedId('test.sig', 'secret')),
  bench('expiringId',                  () => uid.expiringId()),
  bench('entropyId (256 bits)',         () => uid.entropyId({ bits: 256 })),
  bench('adaptiveId',                  () => uid.adaptiveId()),
].forEach(row);

header('Batch & Parser');
const _id = uid.uuid();
[
  bench('batch(nanoId, 100)',          () => uid.batch(uid.nanoId, 100), 1000),
  bench('decodeId (auto-detect)',      () => uid.decodeId(_id)),
  bench('parseId (with metadata)',     () => uid.parseId(_id)),
  bench('validate (regex)',            () => uid.validate(_id)),
].forEach(row);

// ── Competitive Comparison (External) ─────────────────────────────────────────

let extUuid, extNanoid;
try { extUuid = require('uuid'); } catch (e) {}
try { extNanoid = require('nanoid'); } catch (e) {}

if (extUuid || extNanoid) {
  header('Competitive Comparison');
  if (extUuid) row(bench('external: uuid v4', () => extUuid.v4()));
  row(bench('uuid-lab: uuidV4', () => uid.uuidV4()));
  
  if (extNanoid) row(bench('external: nanoid (21)', () => extNanoid.nanoid()));
  row(bench('uuid-lab: nanoId (21)', () => uid.nanoId()));
}

// ── Uniqueness Check ──────────────────────────────────────────────────────────

const N = 10_000;
console.log('\n' + '═'.repeat(COL1 + COL2 + COL3 + COL4 + 4));
console.log(`  UNIQUENESS VERIFICATION (${N.toLocaleString()} ids)`);
console.log('═'.repeat(COL1 + COL2 + COL3 + COL4 + 4));

function checkUnique(label, fn) {
  const ids = new Set();
  for (let i = 0; i < N; i++) ids.add(fn());
  const ok = ids.size === N ? '✅' : '❌';
  console.log(`  ${ok} ${label.padEnd(COL1 - 4)} ${ids.size === N ? 'No collisions' : (N - ids.size) + ' collisions'}`);
}

checkUnique('uuid', uid.uuid);
checkUnique('nanoId', uid.nanoId);
checkUnique('ulid', uid.ulid);
checkUnique('ksuid', uid.ksuid);
checkUnique('snowflakeId', uid.snowflakeId);

console.log('\n  ✅ Benchmark complete\n');

