/* eslint-env es2020 */
'use strict';

/**
 * decoder.js — Reverse ID Decoder & Global Parser
 * Uses validation patterns for robust detection.
 */

const { PATTERNS } = require('./validation');

const _customDecoders = new Map();

function registerDecoder(name, { pattern, decode }) {
  if (!name || typeof decode !== 'function') {
    throw new TypeError('registerDecoder: needs name + decode function');
  }
  _customDecoders.set(name, { pattern, decode });
}

// Extract UUID version
const UUID_VERSION_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-([1-8])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function _decodeUUID(id) {
  if (!PATTERNS.uuid.test(id)) return null;
  
  const m = id.match(UUID_VERSION_RE);
  if (!m) return { type: 'uuid', version: null, raw: id };

  const version = parseInt(m[1], 16);
  const base = { type: `uuid-v${version}`, version, raw: id };

  if (version === 7) {
    const hex = id.replace(/-/g, '');
    const tsMs = Number(BigInt('0x' + hex.slice(0, 12)));
    base.timestamp = tsMs;
    base.date = new Date(tsMs).toISOString();
  }
  if (version === 1) {
    try {
      const hex = id.replace(/-/g, '');
      const t = BigInt('0x' + hex.slice(13, 16) + hex.slice(8, 12) + hex.slice(0, 8));
      const tsMs = Number((t - 122192928000000000n) / 10000n);
      base.timestamp = tsMs;
      base.date = new Date(tsMs).toISOString();
    } catch { /* ignore */ }
  }
  return base;
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function _decodeULID(id) {
  if (!PATTERNS.ulid.test(id)) return null;
  const upper = id.toUpperCase();
  let ts = 0;
  for (let i = 0; i < 10; i++) {
    const idx = CROCKFORD.indexOf(upper[i]);
    if (idx === -1) return null;
    ts = ts * 32 + idx;
  }
  if (ts < 1_000_000_000_000) return null;
  return { type: 'ulid', timestamp: ts, date: new Date(ts).toISOString(), random: upper.slice(10), raw: id };
}

function _decodeKSUID(id) {
  if (!PATTERNS.ksuid.test(id)) return null;
  try {
    let b64 = id.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const buf = Buffer.from(b64, 'base64');
    if (buf.length < 20) return null;
    const epochSec = buf.readUInt32BE(0) + 1400000000;
    if (epochSec < 1_400_000_000 || epochSec > 2_000_000_000) return null;
    return { type: 'ksuid', timestamp: epochSec * 1000, date: new Date(epochSec * 1000).toISOString(), raw: id };
  } catch { return null; }
}

function _decodeSnowflake(id) {
  if (!PATTERNS.snowflake.test(id)) return null;
  try {
    const n = BigInt(id);
    const ts = Number((n >> 22n) + 1262304000000n);
    if (ts < 1_262_304_000_000 || ts > 4_102_444_800_000) return null;
    return {
      type: 'snowflake',
      timestamp: ts,
      date: new Date(ts).toISOString(),
      machineId: Number((n >> 12n) & 0x3FFn),
      sequence: Number(n & 0xFFFn),
      raw: id,
    };
  } catch { return null; }
}

const EU_COUNTRIES = new Set([
  'DE','IE','GB','FR','SE','NL','PL','IT','ES','BE','AT','DK',
  'FI','PT','CZ','RO','HU','SK','BG','HR','LT','LV','EE','SI','CY','LU','MT',
]);
const REGION_CC_MAP = {
  'us-east-1':'US','us-west-2':'US','us-central-1':'US','us-west-1':'US',
  'eu-central-1':'DE','eu-west-1':'IE','eu-west-2':'GB','eu-west-3':'FR',
  'eu-north-1':'SE','eu-south-1':'IT','ap-southeast-1':'SG',
  'ap-northeast-1':'JP','ap-south-1':'IN','ca-central-1':'CA','sa-east-1':'BR',
};

let _topologyMod = null;
function _getTopologyMod() {
  if (_topologyMod === null) {
    try { _topologyMod = require('./topology'); } catch { _topologyMod = false; }
  }
  return _topologyMod || null;
}

function _decodeTopo(id) {
  const topo = _getTopologyMod();
  if (topo && topo.parseTopology) {
    try {
      const parsed = topo.parseTopology(id);
      if (parsed && parsed.country) {
        return {
          type: 'topology',
          country: parsed.country,
          isEU: EU_COUNTRIES.has(parsed.country),
          dc: parsed.dc,
          region: parsed.region,
          raw: id,
        };
      }
    } catch { /* not a topology id */ }
  }

  if (id.startsWith('topo_')) {
    const parts = id.split('_');
    if (parts.length >= 3) {
      try {
        const regionStr = Buffer.from(parts[1], 'hex').toString('utf8');
        const country = REGION_CC_MAP[regionStr] || null;
        if (country) {
          return { type: 'topology', country, isEU: EU_COUNTRIES.has(country), raw: id };
        }
      } catch { /* not hex */ }
      return { type: 'topology', country: null, isEU: false, raw: id };
    }
  }
  return null;
}

let _lifecycleMod = null;
function _getLifecycleMod() {
  if (_lifecycleMod === null) {
    try { _lifecycleMod = require('./lifecycle_enhanced'); } catch { _lifecycleMod = false; }
  }
  return _lifecycleMod || null;
}

function _decodeLifecycle(id) {
  const lc = _getLifecycleMod();
  if (lc && lc.parseLifecycle) {
    try {
      const parsed = lc.parseLifecycle(id);
      if (parsed && parsed.state !== undefined) {
        return { type: 'lifecycle', state: parsed.state, entity: parsed.entity || null, raw: id };
      }
    } catch { /* not a lifecycle id */ }
  }

  if (!id.startsWith('lc_')) return null;
  const parts = id.split('_');
  if (parts.length < 3) return null;
  const state = parts.length >= 4 ? parts[parts.length - 2] : parts[2];
  return { type: 'lifecycle', state: state || null, raw: id };
}

function _decodeExpiring(id) {
  if (!PATTERNS.expiring.test(id)) return null;
  const m = id.match(/^exp_(\d+)_/);
  if (!m) return null;
  const expiresAt = parseInt(m[1]);
  return { type: 'expiring', expiresAt, expiresAtDate: new Date(expiresAt).toISOString(), expired: expiresAt < Date.now(), raw: id };
}

function _decodeDerived(id) { return id.startsWith('drv_') ? { type: 'derived', raw: id } : null; }
function _decodeMigrated(id) {
  if (!/^mig_v\d+_/.test(id)) return null;
  const v = id.match(/^mig_v(\d+)_/);
  return { type: 'migrated', version: v ? parseInt(v[1]) : null, raw: id };
}

function _decodeNanoID(id) {
  if (!PATTERNS.nanoidAny.test(id)) return null;
  if (PATTERNS.uuid.test(id) || PATTERNS.ulid.test(id) || PATTERNS.snowflake.test(id)) return null;
  return { type: 'nanoid', length: id.length, entropyBits: Math.floor(id.length * Math.log2(64)), raw: id };
}

function _decodePrefixed(id) {
  if (!PATTERNS.prefixed.test(id)) return null;
  const m = id.match(/^([a-z]{2,8})[_-]([A-Za-z0-9_-]{4,})$/);
  if (!m) return null;
  return { type: 'prefixed', prefix: m[1], body: m[2], raw: id };
}

function _decodeLegacyInt(id) {
  if (!/^\d{1,15}$/.test(id)) return null;
  return { type: 'legacy-int', value: parseInt(id), raw: id };
}

function decodeId(id) {
  if (typeof id !== 'string' || !id) return { type: 'unknown', raw: id, error: 'not a string' };

  for (const [name, { pattern, decode }] of _customDecoders) {
    if (!pattern || pattern.test(id)) {
      try {
        const r = decode(id);
        if (r) return { ...r, type: r.type || name, raw: id };
      } catch { /* continue */ }
    }
  }

  return (
    _decodeExpiring(id)  ||
    _decodeDerived(id)   ||
    _decodeMigrated(id)  ||
    _decodeTopo(id)      ||
    _decodeLifecycle(id) ||
    _decodeUUID(id)      ||
    _decodeULID(id)      ||
    _decodeSnowflake(id) ||
    _decodeKSUID(id)     ||
    _decodePrefixed(id)  ||
    _decodeLegacyInt(id) ||
    _decodeNanoID(id)    ||
    { type: 'unknown', raw: id }
  );
}

const CONFIDENCE_MAP = {
  'uuid-v4':'high','uuid-v7':'high','uuid-v5':'high','uuid-v3':'high','uuid-v1':'high',
  'uuid':'medium','ulid':'high','ksuid':'high','snowflake':'high',
  'expiring':'high','derived':'high','migrated':'high',
  'topology':'high','lifecycle':'high',
  'prefixed':'medium','nanoid':'medium',
  'legacy-int':'low','unknown':'none',
};

function parseId(id) {
  const decoded = decodeId(id);
  return { type: decoded.type, confidence: CONFIDENCE_MAP[decoded.type] || 'low', decoded };
}

function decodeBatch(ids) {
  if (!Array.isArray(ids)) throw new TypeError('decodeBatch expects an array of strings');
  return ids.map(decodeId);
}

module.exports = { decodeId, parseId, decodeBatch, registerDecoder };