#!/usr/bin/env node
/**
 * Confirm which wallet the wrapper will actually pay from - BEFORE you fund it.
 *
 * Reads the key from the environment. It is never printed, never logged, never written
 * anywhere. Only the derived public address and its balances are shown.
 *
 *   PowerShell:  $env:X402_PRIVATE_KEY="0x..."; npx x402-trinity-whoami
 *   bash:        X402_PRIVATE_KEY=0x... npx x402-trinity-whoami
 *
 * Shard custody (no single stored secret is a spending key):
 *   X402_KEY_SHARD_1, X402_KEY_SHARD_2, ...
 *
 * Check the printed address against your wallet app. If it does not match, STOP -
 * do not send funds anywhere until it does.
 */
import { fromHex, __internals } from '../dist/x402.js';

const { addressOf, toBig, CHAINS, N } = __internals;

const RPCS = {
  'base': 'https://mainnet.base.org',
};
const TESTNETS = new Set();

function loadKey() {
  const shards = Object.keys(process.env)
    .filter(k => /^X402_KEY_SHARD_\d+$/.test(k))
    .sort()
    .map(k => process.env[k]);
  if (shards.length) {
    let d = 0n;
    for (const s of shards) d = (d + toBig(fromHex(s.trim()))) % N;
    return { d, source: `${shards.length} shards (X402_KEY_SHARD_*)` };
  }
  const raw = process.env.X402_PRIVATE_KEY;
  if (!raw) return null;
  const hex = raw.trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(hex)) {
    console.error('\n  X402_PRIVATE_KEY is not a 32-byte hex key (64 hex chars, 0x optional).');
    console.error('  Nothing was read or stored. Fix the value and re-run.\n');
    process.exit(1);
  }
  return { d: toBig(fromHex(hex.startsWith('0x') ? hex : '0x' + hex)), source: 'X402_PRIVATE_KEY' };
}

const loaded = loadKey();
if (!loaded) {
  console.error(`
  No key found in the environment.

  PowerShell:
    $env:X402_PRIVATE_KEY="0xYOUR_KEY"
    npx x402-trinity-whoami

  bash:
    X402_PRIVATE_KEY=0xYOUR_KEY npx x402-trinity-whoami

  Never hardcode the key in source and never commit it.
`);
  process.exit(1);
}
if (loaded.d === 0n || loaded.d >= N) {
  console.error('\n  Key is out of range for secp256k1. Refusing to derive an address.\n');
  process.exit(1);
}

const address = addressOf(loaded.d);
console.log(`\n  key source     ${loaded.source}   (value never printed)`);
console.log(`  PAYS FROM      ${address}`);
console.log(`\n  Check this against your wallet app before sending anything.\n`);

const rpc = async (url, method, params) => {
  try {
    const r = await fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(12000),
    });
    const j = await r.json();
    return j.error ? null : j.result;
  } catch { return null; }
};
const BAL_SEL = '0x70a08231';

console.log('  balances\n');
console.log(`  ${'network'.padEnd(16)} ${'native'.padStart(12)} ${'USDC'.padStart(14)}`);
for (const [net, cfg] of Object.entries(CHAINS)) {
  const url = RPCS[net];
  if (!url) continue;
  const [nat, usdc] = await Promise.all([
    rpc(url, 'eth_getBalance', [address, 'latest']),
    rpc(url, 'eth_call', [{ to: cfg.asset, data: BAL_SEL + address.slice(2).padStart(64, '0') }, 'latest']),
  ]);
  if (nat === null) { console.log(`  ${net.padEnd(16)}   (rpc unreachable)`); continue; }
  const n = Number(toBig(fromHex(nat))) / 1e18;
  const u = usdc ? Number(toBig(fromHex(usdc))) / 1e6 : 0;
  const tag = TESTNETS.has(net) ? '' : '  <- MAINNET, real value';
  console.log(`  ${net.padEnd(16)} ${n.toFixed(6).padStart(12)} ${u.toFixed(6).padStart(14)}${tag}`);
}
console.log(`
  Reminder: use a dedicated wallet holding only what you would accept losing,
  and set policy caps that bound the spend regardless.
`);
