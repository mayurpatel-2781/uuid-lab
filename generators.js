/* eslint-env es2020 */
'use strict';

/**
 * generators.js — Core ID Generator Engine
 * All generators use opts-object API: fn({ size, alphabet, ... })
 * Never positional args — prevents NaN bugs.
 */

// ── Universal Crypto Adapter ──────────────────────────────────────────────────

const _crypto = (() => {
  // 1. Check for Node.js native crypto
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const nc = require('crypto');
      return {
        randomBytes: (n) => nc.randomBytes(n),
        randomInt: (min, max) => nc.randomInt(min, max),
        randomUUID: () => nc.randomUUID ? nc.randomUUID() : null,
        createHash: (alg) => nc.createHash(alg)
      };
    } catch (e) { /* fallback */ }
  }

  // 2. Check for Web Crypto API (Browsers, React Native, Edge)
  const wc = (typeof globalThis !== 'undefined' && globalThis.crypto) || (typeof window !== 'undefined' && window.crypto);
  if (wc && wc.getRandomValues) {
    return {
      randomBytes: (n) => wc.getRandomValues(new Uint8Array(n)),
      randomInt: (min, max) => {
        if (max === undefined) { max = min; min = 0; }
        const range = max - min;
        const b = wc.getRandomValues(new Uint8Array(4));
        const view = new DataView(b.buffer);
        return min + (view.getUint32(0) % range);
      },
      randomUUID: () => wc.randomUUID ? wc.randomUUID() : null,
      createHash: null // Browsers use subtle.digest (async), handled separately
    };
  }

  throw new Error('uuid-lab: No secure crypto implementation found. Ensure globalThis.crypto is available.');
})();

// Helper to get hex from bytes (cross-platform)
const toHex = (buf) => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');

// ── Alphabet Constants ────────────────────────────────────────────────────────
const ALPHA_BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ALPHA_BASE62    = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const ALPHA_BASE36    = '0123456789abcdefghijklmnopqrstuvwxyz';
const ALPHA_HEX       = '0123456789abcdef';
const ALPHA_NUMERIC   = '0123456789';
const ALPHA_ALPHA     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

// ── Core nanoId ───────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random ID (NanoID style).
 * @param {object|number} [opts] Options or size number
 * @param {number} [opts.size] ID length (default 21)
 * @param {string} [opts.alphabet] Custom alphabet
 * @returns {string}
 */
function nanoId(opts = {}) {
  if (typeof opts === 'number') opts = { size: opts };
  const { size = 21, alphabet = ALPHA_BASE64URL } = opts;
  if (typeof size !== 'number' || size < 1) throw new RangeError(`nanoId size must be a positive number, got: ${size}`);

  const bytes = _crypto.randomBytes(size);
  let result  = '';
  for (let i = 0; i < bytes.length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}

// ── UUID Generators (RFC 9562) ────────────────────────────────────────────────

/**
 * Generate a standard UUID (v4 if native available, else fallback).
 * @returns {string}
 */
function uuid() {
  const native = _crypto.randomUUID();
  return native || uuidV4();
}

/**
 * Generate a cryptographically random UUID v4.
 * @returns {string} 36-character UUID string
 */
function uuidV4() {
  const b = _crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

/**
 * Generate a sortable UUID v7.
 * @param {object} [opts] Options
 * @param {number} [opts.timestamp] Custom timestamp in ms
 * @returns {string} 36-character UUID string
 */
function uuidV7(opts = {}) {
  const b = _crypto.randomBytes(16);
  const ms = opts.timestamp || Date.now();
  // ms is 48 bits
  b[0] = (ms / 0x10000000000) & 0xff;
  b[1] = (ms / 0x100000000) & 0xff;
  b[2] = (ms / 0x1000000) & 0xff;
  b[3] = (ms / 0x10000) & 0xff;
  b[4] = (ms / 0x100) & 0xff;
  b[5] = ms & 0xff;
  b[6] = (b[6] & 0x0f) | 0x70; b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

/**
 * Generate a time-based UUID v1.
 * @returns {string}
 */
function uuidV1() {
  const b = _crypto.randomBytes(16);
  // Gregorian time
  const ts = BigInt(Date.now() + 12219292800000) * 10000n;
  const timeHex = ts.toString(16).padStart(15, '0');
  
  // v1: Low-mid-high time
  const h = timeHex;
  const res = [
    h.slice(7, 15),
    h.slice(3, 7),
    '1' + h.slice(0, 3),
    ((b[8] & 0x3f) | 0x80).toString(16).padStart(2, '0') + toHex(b.slice(9, 10)),
    toHex(b.slice(10, 16))
  ];
  return res.join('-');
}

/**
 * Generate a reordered Gregorian UUID v6 (Sortable).
 * @returns {string}
 */
function uuidV6() {
  const b = _crypto.randomBytes(16);
  // Gregorian time: 100ns intervals since Oct 15, 1582
  const ts = BigInt(Date.now() + 12219292800000) * 10000n;
  const timeHex = ts.toString(16).padStart(15, '0');
  
  // v6: High 48 bits, then version, then mid/low bits
  const h = timeHex;
  const res = [
    h.slice(0, 8),
    h.slice(8, 12),
    '6' + h.slice(12, 15),
    ((b[8] & 0x3f) | 0x80).toString(16).padStart(2, '0') + toHex(b.slice(9, 10)),
    toHex(b.slice(10, 16))
  ];
  return res.join('-');
}

/**
 * Generate a custom UUID v8.
 * @param {Uint8Array|number[]} [customBytes] 122 bits of custom data
 * @returns {string}
 */
function uuidV8(customBytes) {
  const b = customBytes ? new Uint8Array(customBytes) : _crypto.randomBytes(16);
  if (b.length < 16) {
    const full = new Uint8Array(16);
    full.set(b);
    _crypto.randomBytes(16 - b.length).forEach((v, i) => full[b.length + i] = v);
    b = full;
  }
  b[6] = (b[6] & 0x0f) | 0x80; // version 8
  b[8] = (b[8] & 0x3f) | 0x80; // variant 1
  const h = toHex(b);
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

/**
 * Generate a namespaced UUID v5 (SHA-1).
 * @param {object|string} [opts] Options or name string
 * @param {string} [opts.name] Name to hash
 * @param {string} [opts.namespace] UUID namespace
 * @returns {string}
 */
function uuidV5(opts = {}) {
  const { name = '', namespace = '6ba7b811-9dad-11d1-80b4-00c04fd430c8' } = typeof opts === 'string' ? { name: opts } : opts;
  if (!_crypto.createHash) throw new Error('uuidV5 (SHA-1) requires Node.js crypto. For browser use, see documentation for async alternatives.');
  const h = _crypto.createHash('sha1').update(namespace + name).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-5${h.slice(13,16)}-${((parseInt(h.slice(16,18),16)&0x3f)|0x80).toString(16)}${h.slice(18,20)}-${h.slice(20,32)}`;
}

/**
 * Generate a namespaced UUID v3 (MD5).
 * @param {object|string} [opts] Options or name string
 * @param {string} [opts.name] Name to hash
 * @param {string} [opts.namespace] UUID namespace
 * @returns {string}
 */
function uuidV3(opts = {}) {
  const { name = '', namespace = '6ba7b811-9dad-11d1-80b4-00c04fd430c8' } = typeof opts === 'string' ? { name: opts } : opts;
  if (!_crypto.createHash) throw new Error('uuidV3 (MD5) requires Node.js crypto.');
  const h = _crypto.createHash('md5').update(namespace + name).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-3${h.slice(13,16)}-${((parseInt(h.slice(16,18),16)&0x3f)|0x80).toString(16)}${h.slice(18,20)}-${h.slice(20,32)}`;
}

// ── Sortable / Time-based ─────────────────────────────────────────────────────

/**
 * Generate a Lexicographically Sortable Identifier (ULID).
 * @param {object} [opts] Options
 * @param {number} [opts.timestamp] Custom timestamp in ms
 * @returns {string} 26-character ULID
 */
function ulid(opts = {}) {
  const C = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const t = opts.timestamp || Date.now();
  let s = '', n = t;
  for (let i = 9; i >= 0; i--) { s = C[n % 32] + s; n = Math.floor(n / 32); }
  s = s.padStart(10, C[0]);
  const r = _crypto.randomBytes(16);
  let rs = '';
  for (let i = 0; i < 16; i++) rs += C[r[i] % 32];
  return (s + rs).slice(0, 26);
}

/**
 * Generate a K-Sortable Unique Identifier (KSUID).
 * @param {object} [opts] Options
 * @param {number} [opts.timestamp] Custom timestamp in ms
 * @returns {string} 27-character KSUID
 */
function ksuid(opts = {}) {
  const t   = Math.floor((opts.timestamp || Date.now()) / 1000) - 1400000000;
  // Browser-safe KSUID (base62 encoding of 4-byte time + 16-byte random)
  const timeBytes = new Uint8Array(4);
  const view = new DataView(timeBytes.buffer);
  view.setUint32(0, t);
  const randBytes = _crypto.randomBytes(16);
  
  // Combine
  const combined = new Uint8Array(20);
  combined.set(timeBytes);
  combined.set(randBytes, 4);

  // Simple base62-like encoding (or base64url if preferred, here following KSUID spec)
  return btoa(String.fromCharCode(...combined)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'').slice(0, 27);
}

let _sfLastTs = 0n;
let _sfSeq = 0n;

/**
 * Generate a Snowflake ID.
 * @param {object} [opts] Options
 * @param {number} [opts.timestamp] Custom timestamp in ms
 * @param {number} [opts.epoch] Custom epoch
 * @param {number} [opts.workerId] 10-bit worker ID
 * @param {number} [opts.sequence] 12-bit sequence (override)
 * @returns {string} Numeric string Snowflake ID
 */
function snowflakeId(opts = {}) {
  const epoch = BigInt(opts.epoch || 1262304000000);
  let now = BigInt(opts.timestamp || Date.now());

  if (opts.timestamp) {
    const seq = BigInt(opts.sequence ?? _crypto.randomInt(4096)) & 0xFFFn;
    const workerId = BigInt(opts.workerId || 0) & 0x3FFn;
    return (((now - epoch) << 22n) | (workerId << 12n) | seq).toString();
  }

  if (now === _sfLastTs) {
    _sfSeq = (_sfSeq + 1n) & 0xFFFn;
    if (_sfSeq === 0n) {
      while (now <= _sfLastTs) {
        now = BigInt(Date.now());
      }
    }
  } else {
    _sfSeq = 0n;
  }
  _sfLastTs = now;

  const workerId = BigInt(opts.workerId || 0) & 0x3FFn;
  const seq = opts.sequence !== undefined ? BigInt(opts.sequence) & 0xFFFn : _sfSeq;

  return (((now - epoch) << 22n) | (workerId << 12n) | seq).toString();
}

// ── Type Registry ─────────────────────────────────────────────────────────────

const TYPE_PREFIXES = {
  user: 'usr', order: 'ord', session: 'ses', invoice: 'inv',
  product: 'prd', event: 'evt', payment: 'pay', ticket: 'tkt',
  document: 'doc', message: 'msg', team: 'tm', workspace: 'ws',
};
const TYPE_REGISTRY = { ...TYPE_PREFIXES };

/**
 * Register custom ID prefixes.
 * @param {Record<string, string>} map Map of type to prefix
 */
function registerTypes(map) {
  if (typeof map !== 'object') throw new TypeError('registerTypes expects an object');
  Object.assign(TYPE_REGISTRY, map);
}

function typedId(opts = {}) {
  const { type, size = 21 } = typeof opts === 'string' ? { type: opts } : opts;
  if (!type) throw new TypeError('typedId requires a type string');
  const prefix = TYPE_REGISTRY[type] || type.slice(0, 3).toLowerCase();
  return `${prefix}_${nanoId({ size })}`;
}

// ── Human-readable ────────────────────────────────────────────────────────────

const ADJECTIVES = [
  'brave','calm','dark','eager','fair','grand','happy','kind',
  'lively','merry','noble','proud','quick','rare','swift','true',
  'vivid','warm','young','zesty','bold','cool','deep','pure',
];
const NOUNS = [
  'hawk','lake','moon','pine','reef','sage','tide','wolf',
  'apex','bolt','cave','dusk','echo','fern','gale','haze',
];

/**
 * Generate a human-friendly ID (e.g. 'brave-wolf-1234').
 * @param {object} [opts] Options
 * @param {string} [opts.separator] Default '-'
 * @param {number} [opts.words] Number of words (default 2)
 * @param {boolean} [opts.withNumber] Include random number
 * @returns {string}
 */
function humanId(opts = {}) {
  const { separator = '-', words = 2, withNumber = true } = opts;
  const pick = arr => arr[_crypto.randomInt(arr.length)];
  const parts = Array.from({ length: words }, (_, i) =>
    i % 2 === 0 ? pick(ADJECTIVES) : pick(NOUNS)
  );
  if (withNumber) parts.push(String(_crypto.randomInt(1000, 9999)));
  return parts.join(separator);
}

// ── Sequential ────────────────────────────────────────────────────────────────

let _seq = 0;
/**
 * Generate a sequential padded ID.
 * @param {object} [opts] Options
 * @param {number} [opts.pad] Padding length
 * @param {string} [opts.prefix] Optional prefix
 * @returns {string}
 */
function sequentialId(opts = {}) {
  const { pad = 8, prefix = '' } = opts;
  const n = String(++_seq).padStart(pad, '0');
  return prefix ? `${prefix}_${n}` : n;
}

/** Reset global sequence counter */
function resetSequence(n = 0) { _seq = n; }
/** Get current global sequence counter */
function getSequence()        { return _seq; }

// ── Pattern-based ─────────────────────────────────────────────────────────────

/**
 * Generate an ID from a pattern (x: hex, X: HEX, a: alpha, A: ALPHA, 9: numeric).
 * @param {string} pattern Pattern string
 * @returns {string}
 */
function fromPattern(pattern) {
  if (typeof pattern !== 'string') throw new TypeError('pattern must be a string');
  return pattern.replace(/[xXaA9]/g, c => {
    switch (c) {
      case 'x': return _crypto.randomInt(16).toString(16);
      case 'X': return _crypto.randomInt(16).toString(16).toUpperCase();
      case 'a': return ALPHA_ALPHA[_crypto.randomInt(ALPHA_ALPHA.length)];
      case 'A': return ALPHA_ALPHA[_crypto.randomInt(ALPHA_ALPHA.length)].toUpperCase();
      case '9': return String(_crypto.randomInt(10));
      default:  return c;
    }
  });
}

module.exports = {
  nanoId,
  uuid,
  uuidV1,
  uuidV4,
  uuidV6,
  uuidV7,
  uuidV8,
  uuidV5,
  uuidV3,
  ulid,
  ksuid,
  snowflakeId,
  typedId,
  registerTypes,
  TYPE_REGISTRY,
  humanId,
  sequentialId,
  resetSequence,
  getSequence,
  fromPattern,
  // Alphabet exports
  ALPHA_BASE64URL,
  ALPHA_BASE62,
  ALPHA_BASE36,
  ALPHA_HEX,
  ALPHA_NUMERIC,
  ALPHA_ALPHA,
};

