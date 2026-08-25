/**
 * Build the distributable package.
 *
 *   node tools/build.mjs
 *
 * Emits, for each entry point:
 *   dist/<name>.js     ESM, type-stripped, unminified (readable - this code moves money,
 *                      so a user should be able to read what they are running)
 *   dist/<name>.min.js ESM, minified, for size-sensitive edge bundles
 *   dist/<name>.d.ts   types, emitted by tsc
 *
 * Then verifies the built artifact actually works rather than assuming it does.
 */
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const ROOT = new URL('..', import.meta.url);
const ENTRIES = ['x402', 'seller', 'budget-file', 'evm-tx'];

const dist = new URL('dist/', ROOT);
if (existsSync(dist)) rmSync(dist, { recursive: true });
mkdirSync(dist, { recursive: true });

console.log('\nbuilding x402-trinity\n' + '-'.repeat(64));

const rows = [];
for (const name of ENTRIES) {
  const src = readFileSync(new URL(`src/${name}.ts`, ROOT), 'utf8');

  // Local imports must resolve after the .ts extension is dropped.
  const rewrite = s => s.replace(/from '\.\/([a-z0-9-]+)\.ts'/g, "from './$1.js'");

  const plain = await esbuild.transform(rewrite(src), { loader: 'ts', format: 'esm', target: 'es2022' });
  const min = await esbuild.transform(rewrite(src), { loader: 'ts', format: 'esm', target: 'es2022', minify: true });

  writeFileSync(new URL(`dist/${name}.js`, ROOT), plain.code);
  writeFileSync(new URL(`dist/${name}.min.js`, ROOT), min.code);

  const gz = gzipSync(min.code, { level: 9 }).length;
  rows.push([name, plain.code.length, min.code.length, gz]);
}

// types
execFileSync(process.execPath, [fileURLToPath(new URL('node_modules/typescript/lib/tsc.js', ROOT)), '-p', 'tsconfig.json'],
  { cwd: fileURLToPath(ROOT), stdio: 'inherit' });
// tsc writes .d.ts referencing './x402.ts'; point them at the .js
for (const name of ENTRIES) {
  const p = new URL(`dist/${name}.d.ts`, ROOT);
  if (existsSync(p)) writeFileSync(p, readFileSync(p, 'utf8').replace(/from '\.\/([a-z0-9-]+)\.ts'/g, "from './$1.js'"));
}

const kb = b => (b / 1024).toFixed(2) + ' KB';
console.log(`\n  ${'module'.padEnd(14)} ${'readable'.padStart(10)} ${'minified'.padStart(10)} ${'gzipped'.padStart(10)}`);
for (const [n, a, b, c] of rows) console.log(`  ${n.padEnd(14)} ${kb(a).padStart(10)} ${kb(b).padStart(10)} ${kb(c).padStart(10)}`);
console.log(`\n  runtime dependencies: 0`);

// ---- verify the BUILT artifact, not the source
console.log('\nverifying dist/\n' + '-'.repeat(64));
const M = await import(new URL('dist/x402.js', ROOT).href);
const { addressOf, domainSep, digest, beBytes, CHAINS } = M.__internals;
const AUTH = {
  from: '0x2c7536e3605d9c16a7a3d7b1898e529396a65c23', to: '0x9f2c4a1b3d5e6f708192a3b4c5d6e7f809a1b2c3',
  value: '1500', validAfter: '0', validBefore: '9999999999',
  nonce: '0x0101010101010101010101010101010101010101010101010101010101010101',
};
let bad = 0;
const ck = (n, c, d = '') => { console.log(`  ${c ? 'ok  ' : 'FAIL'}  ${n}${d ? '  ' + d : ''}`); if (!c) bad++; };
ck('keccak256 vector', M.toHex(M.keccak256(new TextEncoder().encode(''))) === '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
ck('address vector', addressOf(1n) === '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
// The library ships MAINNET ONLY, so the domain params are passed explicitly rather than
// looked up. This still proves the encoder against the digest the deployed Base Sepolia
// contract accepted - the strongest single piece of ground truth we have.
ck('contract-accepted digest (Base Sepolia ground truth)',
  M.toHex(beBytes(digest(domainSep('USDC', '2', 84532, '0x036cbd53842c5426634e7929541ec2318f3dcf7e'), AUTH), 32))
  === '0x4d1a73267fb621d8b6b61b915f2232e8f820417dd37841becf57268c1e010799');
// and the same encoder must produce Base MAINNET's separator, which is a different value
ck('Base MAINNET domain separator',
  M.toHex(domainSep('USD Coin', '2', 8453, CHAINS['base'].asset))
  === '0x02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f');
ck('Base only - the one pair that has moved real money', Object.keys(CHAINS).length === 1 && 'base' in CHAINS, Object.keys(CHAINS).join(', '));
ck('NO testnets shipped', !Object.keys(CHAINS).some(k => /sepolia|fuji|testnet|goerli/i.test(k)), Object.keys(CHAINS).join(', '));

// The README's seller example is the first code most people run. It has been wrong before:
// it omitted `facilitator` and `nonceStore` (both throw) and passed receiptHeader() as the
// Response init instead of its headers, which silently drops the receipt. Check the shape.
{
  const rd = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const sell = rd.slice(rd.indexOf('## Sell'));
  const block = sell.slice(sell.indexOf('```js') + 5, sell.indexOf('```', sell.indexOf('```js') + 5));
  ck('README seller example passes a facilitator', /facilitator:/.test(block));
  ck('README seller example passes a durable nonceStore', /nonceStore:/.test(block));
  ck('README seller example puts the receipt in headers, not the init',
     /\{\s*headers:\s*seller\.receiptHeader/.test(block), block.match(/new Response\([^)]*\)/)?.[0]);
  ck('README does not promise a Python seller',
     !/Buyer \*and\* seller\. TypeScript \*and\* Python/.test(rd));
}
ck('createX402Fetch exported', typeof M.createX402Fetch === 'function');

const S = await import(new URL('dist/seller.js', ROOT).href);
ck('seller module loads', typeof S.createX402Seller === 'function');
const B = await import(new URL('dist/budget-file.js', ROOT).href);
ck('budget-file module loads', typeof B.createFileBudgetStore === 'function');

// a real 402 -> 200 round trip through the BUILT bundle
const f = M.createX402Fetch({
  privateKey: '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  mode: 'edge', acknowledgeEphemeralBudget: true,
  policy: { maxAmountPerRequest: '5000', totalBudget: '100000' },
  baseFetch: async (i) => {
    const rq = i instanceof Request ? i : new Request(i);
    if (rq.headers.get('x-payment')) return new Response('{"ok":1}', { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response(JSON.stringify({
      x402Version: 1, accepts: [{ scheme: 'exact', network: 'base', payTo: '0x9f2c4a1b3d5e6f708192a3b4c5d6e7f809a1b2c3', asset: CHAINS['base'].asset, maxAmountRequired: '1500', maxTimeoutSeconds: 120 }],
    }), { status: 402, headers: { 'content-type': 'application/json' } });
  },
});
ck('402 -> 200 round trip through dist/', (await f('https://t.local/x')).status === 200);

console.log('-'.repeat(64));
console.log(`  ${bad === 0 ? 'BUILD VERIFIED' : 'BUILD BROKEN (' + bad + ' failures)'}\n`);
process.exit(bad ? 1 : 0);
