#!/usr/bin/env node
/**
 * x402-trinity MCP server - lets an AI agent buy things.
 *
 * MCP is how an agent gets tools; x402 is how it pays. This exposes three:
 *
 *   check_price     look at what a resource costs WITHOUT paying
 *   pay_and_fetch   fetch it, paying the 402 if it is within your limits
 *   wallet_status   address, on-chain balance, what has been spent
 *
 * Transport is stdio: newline-delimited JSON-RPC 2.0, per the MCP spec. stdout carries
 * protocol messages ONLY - every log line goes to stderr, because a stray console.log
 * on stdout corrupts the stream and the client disconnects.
 *
 * ─── THIS SPENDS REAL MONEY ──────────────────────────────────────────────────
 * A model decides when to call these tools. It cannot be reasoned with about budgets,
 * and a paywalled page can say anything it likes about its own price. So the limits are
 * NOT parameters the model can set - they come from the environment, and the server
 * refuses to start without them:
 *
 *   X402_PRIVATE_KEY      required. Never accepted as a tool argument, never echoed.
 *   X402_MAX_PER_REQUEST  required. Atomic units, e.g. 50000 = $0.05.
 *   X402_TOTAL_BUDGET     required. The ceiling for this server's whole lifetime.
 *   X402_BUDGET_FILE      strongly recommended - survives restarts. Without it the
 *                         ceiling resets every time the server is relaunched, which
 *                         turns a lifetime cap into a per-session one.
 *   X402_ALLOW_HOSTS      optional comma-separated allowlist. With it set, nothing
 *                         else can be paid however convincing the 402 looks.
 *   X402_NETWORKS         optional, default "base".
 *
 * Use a dedicated wallet holding only what you would accept losing.
 * ─────────────────────────────────────────────────────────────────────────────
 */
import { createInterface } from 'node:readline';
import { createX402Fetch, fromHex, __internals } from '../dist/x402.js';
import { createFileBudgetStore } from '../dist/budget-file.js';
import { createRpc, selector } from '../dist/evm-tx.js';

const { toBig, CHAINS } = __internals;
const VERSION = '0.1.0';
const PROTOCOL = '2025-06-18';

const log = (...a) => process.stderr.write('[x402-trinity] ' + a.join(' ') + '\n');
const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');

/* ------------------------------- config ------------------------------- */

function required(name) {
  const v = process.env[name];
  if (!v) {
    log(`FATAL: ${name} is not set. This server spends real money and refuses to run`);
    log('       without explicit limits. See the header of mcp/server.mjs.');
    process.exit(1);
  }
  return v;
}

const KEY = required('X402_PRIVATE_KEY');
const MAX_PER_REQUEST = required('X402_MAX_PER_REQUEST');
const TOTAL_BUDGET = required('X402_TOTAL_BUDGET');
const BUDGET_FILE = process.env.X402_BUDGET_FILE || null;
const ALLOW_HOSTS = (process.env.X402_ALLOW_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean);
const NETWORKS = (process.env.X402_NETWORKS || 'base').split(',').map(s => s.trim()).filter(Boolean);

for (const [n, v] of [['X402_MAX_PER_REQUEST', MAX_PER_REQUEST], ['X402_TOTAL_BUDGET', TOTAL_BUDGET]]) {
  if (!/^[0-9]+$/.test(v) || BigInt(v) <= 0n) { log(`FATAL: ${n} must be a positive whole number of atomic units`); process.exit(1); }
}
if (BigInt(MAX_PER_REQUEST) > BigInt(TOTAL_BUDGET)) {
  log('FATAL: X402_MAX_PER_REQUEST exceeds X402_TOTAL_BUDGET'); process.exit(1);
}

const usd = (atomic) => '$' + (Number(atomic) / 1e6).toFixed(6);

/**
 * A challenge names its chain either by short name ("base") or CAIP-2 ("eip155:8453"),
 * and real sellers use the latter. The wrapper normalizes both; check_price has to do the
 * same or it reports a perfectly payable resource as off-limits and the agent skips a
 * purchase it could have made. Caught by running against a real seller - the stub used
 * short names and hid it.
 */
const CAIP2 = {};
for (const [name, spec] of Object.entries(CHAINS)) CAIP2['eip155:' + spec.id] = name;
const normNet = (n) => { const x = String(n ?? '').toLowerCase().trim(); return CAIP2[x] ?? x; };

const x402Fetch = createX402Fetch({
  privateKey: KEY,
  ...(BUDGET_FILE ? { budgetStore: createFileBudgetStore(BUDGET_FILE) } : { acknowledgeEphemeralBudget: true }),
  policy: {
    maxAmountPerRequest: MAX_PER_REQUEST,
    totalBudget: TOTAL_BUDGET,
    allowNetworks: NETWORKS,
    ...(ALLOW_HOSTS.length ? { allowHosts: ALLOW_HOSTS } : {}),
  },
  onPayment: (i) => log(`paid ${usd(i.value)} to ${i.payTo} on ${i.network}`),
  onDecline: (i) => log(`declined: ${i.reason}`),
  surcharge: { onNotice: (m) => log(m) },
});

log(`ready - wallet ${x402Fetch.address}`);
log(`limits ${usd(MAX_PER_REQUEST)}/request, ${usd(TOTAL_BUDGET)} total` +
    (BUDGET_FILE ? `, durable (${BUDGET_FILE})` : ', EPHEMERAL - resets on restart'));
if (!ALLOW_HOSTS.length) log('WARNING: no X402_ALLOW_HOSTS set - any host may be paid, up to the budget');

/* -------------------------------- tools -------------------------------- */

const TOOLS = [
  {
    name: 'check_price',
    description:
      'Look at what a paid resource costs WITHOUT paying for it. Fetches the URL, and if ' +
      'it answers 402 Payment Required, reports the price, recipient, chain and whether it ' +
      'falls within the configured spending limits. Use this before pay_and_fetch when the ' +
      'cost matters, or to check whether a URL is paywalled at all.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'The resource to price. Must be http(s).' } },
      required: ['url'],
    },
  },
  {
    name: 'pay_and_fetch',
    description:
      'Fetch a resource, paying automatically if it answers 402 Payment Required. THIS ' +
      'SPENDS REAL MONEY from the configured wallet. The payment is refused unless it is ' +
      'within the per-request cap, the remaining lifetime budget, the allowed hosts and the ' +
      'allowed chains - those limits are set by the operator and cannot be raised from here. ' +
      'If a resource is not paywalled it is simply fetched, costing nothing.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The resource to fetch. Must be http(s).' },
        method: { type: 'string', description: 'HTTP method. Default GET.' },
        max_response_chars: { type: 'number', description: 'Truncate the body to this length. Default 20000.' },
      },
      required: ['url'],
    },
  },
  {
    name: 'wallet_status',
    description:
      'Report the paying wallet: its address, its on-chain USDC balance, how much has been ' +
      'spent so far and how much of the budget remains. Reads only - never moves money and ' +
      'never reveals the private key.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const text = (s) => ({ content: [{ type: 'text', text: s }] });
const fail = (s) => ({ content: [{ type: 'text', text: s }], isError: true });

function checkUrl(u) {
  let parsed;
  try { parsed = new URL(u); } catch { return 'Not a valid URL: ' + u; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'Only http and https are supported, got ' + parsed.protocol;
  if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(parsed.hostname)) {
    return `Host ${parsed.hostname} is not in the allowlist. Allowed: ${ALLOW_HOSTS.join(', ')}`;
  }
  return null;
}

async function checkPrice({ url }) {
  const bad = checkUrl(url);
  if (bad) return fail(bad);
  let res;
  try { res = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20000) }); }
  catch (e) { return fail('Could not reach it: ' + (e.message ?? e)); }

  if (res.status !== 402) {
    return text(`Not paywalled. ${url} answered HTTP ${res.status} with no payment required.`);
  }

  // The challenge rides in a header on v2, in the body on v1.
  let challenge = null;
  const hdr = res.headers.get('payment-required');
  if (hdr) { try { challenge = JSON.parse(hdr); } catch { /* fall through to the body */ } }
  if (!challenge) { try { challenge = await res.json(); } catch { /* neither parsed */ } }

  const accepts = challenge?.accepts;
  if (!Array.isArray(accepts) || !accepts.length) {
    return fail(`${url} answered 402 but its challenge could not be parsed, so there is nothing safe to pay.`);
  }

  const lines = [`${url} costs money.`, ''];
  for (const a of accepts) {
    const amount = String(a.amount ?? a.maxAmountRequired ?? '?');
    const ok = /^[0-9]+$/.test(amount);
    const over = ok && BigInt(amount) > BigInt(MAX_PER_REQUEST);
    const spent = BigInt(x402Fetch.stats().spent);
    const left = BigInt(TOTAL_BUDGET) - spent;
    const overBudget = ok && BigInt(amount) > left;
    lines.push(
      `  price     ${ok ? usd(amount) : amount} (${amount} atomic)`,
      `  to        ${a.payTo ?? '?'}`,
      `  chain     ${a.network ?? '?'}`,
      `  scheme    ${a.scheme ?? '?'}`,
      `  payable   ${over ? `NO - over the ${usd(MAX_PER_REQUEST)} per-request cap`
                  : overBudget ? `NO - only ${usd(left)} of budget remains`
                  : !NETWORKS.includes(normNet(a.network)) ? `NO - ${a.network} is not an allowed chain`
                  : 'yes'}`,
      '');
  }
  lines.push('Nothing was paid. Call pay_and_fetch to actually buy it.');
  return text(lines.join('\n'));
}

async function payAndFetch({ url, method, max_response_chars }) {
  const bad = checkUrl(url);
  if (bad) return fail(bad);

  const before = BigInt(x402Fetch.stats().spent);
  let res;
  try { res = await x402Fetch(url, { method: method || 'GET' }); }
  catch (e) { return fail('Request failed: ' + (e.message ?? e)); }

  // Settle the protocol fee before returning. It is normally handed off in a background
  // lane scheduled with setTimeout, which is fine in a long-lived process but loses the fee
  // if the server is stopped right after a tool call - measured on mainnet: the purchase
  // settled and the fee did not. A tool call should not return with money still in flight.
  try { await x402Fetch.flushFees(); } catch { /* never let this break the purchase */ }

  const spent = BigInt(x402Fetch.stats().spent) - before;
  let body = '';
  try { body = await res.text(); } catch { body = '(body could not be read)'; }
  const cap = Number(max_response_chars) > 0 ? Number(max_response_chars) : 20000;
  const truncated = body.length > cap;
  if (truncated) body = body.slice(0, cap);

  if (res.status === 402) {
    return fail(`Payment was DECLINED, so nothing was bought and nothing was spent.\n` +
                `The server still wants payment. Check the server log for the reason - usually the ` +
                `price is over a cap, the host is not allowed, or the budget is exhausted.\n\n${body}`);
  }
  if (res.status === 503) {
    return fail(`The seller accepted the payment but could not settle it, and returned 503.\n` +
                `Nothing was charged twice - the same authorization is held and can be retried.\n\n${body}`);
  }

  const head = spent > 0n
    ? `HTTP ${res.status} - paid ${usd(spent)}. Remaining budget ${usd(BigInt(TOTAL_BUDGET) - BigInt(x402Fetch.stats().spent))}.`
    : `HTTP ${res.status} - no payment was needed.`;
  return text(head + (truncated ? ` Body truncated to ${cap} characters.` : '') + '\n\n' + body);
}

async function walletStatus() {
  const s = x402Fetch.stats();
  const lines = [
    `address    ${x402Fetch.address}`,
    `spent      ${usd(s.spent)} of ${usd(TOTAL_BUDGET)}`,
    `remaining  ${usd(BigInt(TOTAL_BUDGET) - BigInt(s.spent))}`,
    `per call   ${usd(MAX_PER_REQUEST)} maximum`,
    `payments   ${s.payments}`,
    `budget     ${BUDGET_FILE ? 'durable, ' + BUDGET_FILE : 'EPHEMERAL - resets when this server restarts'}`,
    `hosts      ${ALLOW_HOSTS.length ? ALLOW_HOSTS.join(', ') : 'ANY (no allowlist set)'}`,
    `chains     ${NETWORKS.join(', ')}`,
  ];
  for (const net of NETWORKS) {
    const c = CHAINS[net];
    if (!c?.rpc?.length) continue;
    try {
      const rpc = createRpc({ urls: c.rpc });
      const raw = await rpc('eth_call', [{
        to: c.asset,
        data: selector('balanceOf(address)') + x402Fetch.address.slice(2).toLowerCase().padStart(64, '0'),
      }, 'latest']);
      lines.push(`balance    ${usd(toBig(fromHex(raw)))} USDC on ${net}`);
    } catch (e) { lines.push(`balance    ${net}: could not read (${String(e.message ?? e).slice(0, 60)})`); }
  }
  return text(lines.join('\n'));
}

const HANDLERS = { check_price: checkPrice, pay_and_fetch: payAndFetch, wallet_status: walletStatus };

/* ------------------------------ transport ------------------------------ */

async function handle(msg) {
  const { id, method, params } = msg;
  const reply = (result) => send({ jsonrpc: '2.0', id, result });
  const error = (code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize':
      return reply({
        protocolVersion: PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: { name: 'x402-trinity', version: VERSION },
        instructions:
          'Tools for buying paywalled resources with USDC. pay_and_fetch spends real money ' +
          'within limits the operator set and you cannot change. Use check_price first when ' +
          'the cost matters. Never ask the user for a private key - this server already has one.',
      });

    case 'notifications/initialized':
      return;                                  // notification: no id, no response

    case 'ping':
      return reply({});

    case 'tools/list':
      return reply({ tools: TOOLS });

    case 'tools/call': {
      const fn = HANDLERS[params?.name];
      if (!fn) return error(-32602, `Unknown tool: ${params?.name}`);
      try { return reply(await fn(params.arguments ?? {})); }
      catch (e) {
        log(`tool ${params.name} threw: ${e.stack ?? e}`);
        return reply(fail('The tool failed: ' + (e.message ?? e)));
      }
    }

    default:
      if (id === undefined) return;            // unknown notification: ignore
      return error(-32601, `Method not found: ${method}`);
  }
}

const rl = createInterface({ input: process.stdin });
rl.on('line', async (line) => {
  const t = line.trim();
  if (!t) return;
  let msg;
  try { msg = JSON.parse(t); }
  catch { return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  try { await handle(msg); }
  catch (e) { log('handler threw: ' + (e.stack ?? e)); }
});
rl.on('close', () => process.exit(0));
