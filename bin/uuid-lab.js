#!/usr/bin/env node
'use strict';

/**
 * uuid-lab CLI — npx uuid-lab <command> [options]
 */

const uid = require('../index.js');
const pkg = require('../package.json');

const argv   = process.argv.slice(2);
const command = argv[0];
const args    = [];
const flags   = {};

for (let i = 1; i < argv.length; i++) {
  if (argv[i].startsWith('--')) {
    const key = argv[i].slice(2);
    const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    flags[key] = isNaN(val) ? val : Number(val);
  } else {
    args.push(argv[i]);
  }
}

const count = flags.count || flags.n || 1;

function output(data) {
  if (flags.json) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  if (Array.isArray(data)) {
    data.forEach(d => console.log(d));
  } else if (typeof data === 'object') {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

const GENERATORS = {
  nanoid:       () => uid.nanoId({ size: flags.size }),
  uuid:         () => uid.uuid(),
  uuidV1:       () => uid.uuidV1 ? uid.uuidV1() : 'v1 not implemented',
  uuidV3:       () => uid.uuidV3({ name: flags.name || 'test' }),
  uuidV4:       () => uid.uuidV4(),
  uuidV5:       () => uid.uuidV5({ name: flags.name || 'test' }),
  uuidV6:       () => uid.uuidV6(),
  uuidV7:       () => uid.uuidV7(),
  uuidV8:       () => uid.uuidV8(),
  ulid:         () => uid.ulid(),
  ksuid:        () => uid.ksuid(),
  snowflake:    () => uid.snowflakeId(),
  human:        () => uid.humanId(),
  meaningful:   () => uid.meaningfulId({ words: flags.words || 2 }),
  pronounceable:() => uid.pronounceableId({ length: flags.size || 8 }),
  fuzzy:        () => uid.fuzzyId({ size: flags.size || 16 }),
  emoji:        () => uid.emojiId({ size: flags.size || 5 }),
  short:        () => uid.shortId({ size: flags.size || 8 }),
  visual:       () => uid.visualId({ size: flags.size || 16 }),
  timestamp:    () => uid.timestampId({ prefix: flags.prefix }),
  compact:      () => uid.compactId(),
  offline:      () => uid.offlineId(),
  otp:          () => uid.otpToken(),
  typed:        () => uid.typedId(flags.type || flags.t || 'item'),
  adaptive:     () => uid.adaptiveId(flags.usecase || flags.u || 'session'),
  prefixed:     () => uid.prefixedId({ prefix: flags.prefix || flags.p || 'id', size: flags.size || 12 }),
};

switch (command) {
  case 'generate':
  case 'gen':
  case 'g': {
    const type = args[0] || 'nanoid';
    const gen  = GENERATORS[type];
    if (!gen) {
      console.error(`Unknown type: "${type}"\nAvailable: ${Object.keys(GENERATORS).join(', ')}`);
      process.exit(1);
    }
    const ids = Array.from({ length: Math.min(count, 100000) }, () => gen());
    output(ids.length === 1 ? ids[0] : ids);
    break;
  }

  case 'decode':
  case 'parse': {
    const id = args[0];
    if (!id) { console.error('Usage: uuid-lab decode <id>'); process.exit(1); }
    output(uid.decodeId(id));
    break;
  }

  case 'validate': {
    const id = args[0];
    if (!id) { console.error('Usage: uuid-lab validate <id>'); process.exit(1); }
    output(uid.parseId(id));
    break;
  }

  case 'inspect':
  case 'info': {
    const id = args[0];
    if (!id) { console.error('Usage: uuid-lab inspect <id>'); process.exit(1); }
    output(uid.inspectId(id));
    break;
  }

  case 'benchmark':
  case 'bench': {
    console.log('Running production benchmark suite...');
    require('../benchmark.js');
    break;
  }

  case 'scan': {
    const id = args[0];
    if (!id) { console.error('Usage: uuid-lab scan <id>'); process.exit(1); }
    const result = uid.scanForPII(id);
    if (result.clean) console.log('✅ No PII detected');
    else { console.log('⚠️  PII found:', result.findings.map(f => f.type || f).join(', ')); }
    if (flags.json) output(result);
    break;
  }

  case 'entropy': {
    const id = args[0] || uid.nanoId();
    output(uid.analyzeEntropy(id));
    break;
  }

  case 'compress': {
    const id = args[0];
    if (!id) { console.error('Usage: uuid-lab compress <id>'); process.exit(1); }
    const compressed = uid.compressId(id);
    console.log(`Original  (${id.length} chars): ${id}`);
    console.log(`Compressed (${compressed.length} chars): ${compressed}`);
    console.log(`Savings: ${id.length - compressed.length} chars (${Math.round((1 - compressed.length/id.length)*100)}%)`);
    break;
  }

  case 'formats': {
    console.log('Available types:');
    Object.keys(GENERATORS).forEach(t => console.log(`  ${t}`));
    break;
  }

  case 'version':
  case '-v':
  case '--version': {
    console.log(`uuid-lab v${pkg.version}`);
    break;
  }

  case 'help':
  case '--help':
  case '-h':
  default: {
    console.log(`
uuid-lab — Production-grade ID toolkit v${pkg.version}

Usage:
  uuid-lab <command> [options]

Commands:
  generate <type>     Generate IDs (alias: gen, g)
  decode <id>         Decode any ID type
  validate <id>       Validate & detect type
  inspect <id>        Full ID inspection (with metadata)
  benchmark           Run performance benchmarks
  scan <id>           PII/Security scanner
  entropy <id>        Entropy analysis
  compress <id>       Compress UUID to Base62
  formats             List all generator types
  version             Show version

Generate types:
  nanoid, uuid, ulid, ksuid, snowflake, human, meaningful,
  pronounceable, fuzzy, emoji, short, visual, timestamp,
  compact, offline, otp, typed, adaptive, prefixed

Options:
  --count <n>         Number of IDs to generate
  --size <n>          ID length
  --prefix <str>      Prefix for prefixed IDs
  --type <str>        Type for typedId
  --usecase <str>     Use case for adaptiveId
  --ttl <str>         TTL for expiring IDs (1h, 1d, 7d)
  --json              Output raw JSON
  --words <n>         Word count for meaningful IDs

Examples:
  uuid-lab generate nanoid --count 5
  uuid-lab benchmark
  uuid-lab decode 01ARZ3NDEKTSV4RRFFQ69G5FAV
`);
    break;
  }
}

