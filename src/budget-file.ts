/**
 * File-backed durable budget store. OPTIONAL - not part of the core, so it does not
 * count against the wrapper's footprint. Import it only if you want one.
 *
 * Needs no Cloudflare, no database, no network. Works anywhere Node/Bun/Deno runs:
 * your laptop, a VPS, a Raspberry Pi, a robotics controller.
 *
 *     import { createX402Fetch } from './x402.ts';
 *     import { createFileBudgetStore } from './budget-file.ts';
 *
 *     const x402Fetch = createX402Fetch({
 *       privateKey: process.env.X402_PRIVATE_KEY,
 *       policy: { maxAmountPerRequest: '5000', totalBudget: '1000000', allowNetworks: ['base'] },
 *       budgetStore: createFileBudgetStore('./.x402-budget.json'),
 *     });
 *
 * The spend total survives process restarts, which is the entire point: an in-memory
 * budget resets every time the process starts, so on mainnet it caps nothing.
 *
 * Concurrency: uses an exclusive lock file (O_EXCL), so multiple processes on the same
 * machine cannot both pass the same check. It does NOT coordinate across machines - for
 * that, back the same interface with Redis/Postgres/Workers KV instead.
 */
import { openSync, closeSync, unlinkSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';

export interface BudgetStore {
  reserve: (amount: bigint, totalBudget: bigint) => Promise<boolean>;
  release?: (amount: bigint) => Promise<void>;
  /** Current spend, for reporting. */
  spent: () => bigint;
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export function createFileBudgetStore(path: string, opts: { lockTimeoutMs?: number } = {}): BudgetStore {
  const lockPath = path + '.lock';
  const timeout = opts.lockTimeoutMs ?? 5000;

  const read = (): bigint => {
    if (!existsSync(path)) return 0n;
    try {
      const j = JSON.parse(readFileSync(path, 'utf8'));
      const v = BigInt(j.spent ?? '0');
      return v < 0n ? 0n : v;
    } catch {
      // A corrupt ledger must NOT read as zero - that would silently reset the budget
      // and re-open unlimited spending. Fail closed instead.
      throw new Error(`x402 budget file is unreadable: ${path}. Refusing to treat it as zero spend.`);
    }
  };

  const write = (v: bigint): void => {
    const tmp = path + '.tmp';
    writeFileSync(tmp, JSON.stringify({ spent: v.toString(), updated: new Date().toISOString() }));
    renameSync(tmp, path);        // atomic replace on the same filesystem
  };

  async function withLock<T>(fn: () => T): Promise<T> {
    const deadline = Date.now() + timeout;
    let fd: number | undefined;
    for (;;) {
      try { fd = openSync(lockPath, 'wx'); break; }        // O_CREAT|O_EXCL - one winner
      catch {
        if (Date.now() > deadline) throw new Error(`x402 budget lock timed out: ${lockPath}`);
        await sleep(15);
      }
    }
    try { return fn(); }
    finally {
      try { closeSync(fd!); } catch { /* already closed */ }
      try { unlinkSync(lockPath); } catch { /* already gone */ }
    }
  }

  return {
    /** Atomic check-and-increment. Returns false if the payment would exceed the budget. */
    reserve: (amount, totalBudget) => withLock(() => {
      const now = read();
      if (now + amount > totalBudget) return false;
      write(now + amount);
      return true;
    }),
    release: (amount) => withLock(() => {
      const now = read();
      write(now - amount < 0n ? 0n : now - amount);
    }),
    spent: () => read(),
  };
}


/**
 * File-backed fee tally. Node-only, same atomic-rename pattern. `accrued` is ATOMIC x 1e6
 * so sub-unit fees are not rounded away; `count` is payments since the last settlement.
 */
export function createFileFeeStore(path: string, opts: { lockTimeoutMs?: number } = {}) {
  const lockPath = path + '.lock';
  const timeout = opts.lockTimeoutMs ?? 5000;

  const read = (): { accrued: bigint; count: bigint } => {
    if (!existsSync(path)) return { accrued: 0n, count: 0n };
    try {
      const j = JSON.parse(readFileSync(path, 'utf8'));
      return { accrued: BigInt(j.accruedScaled ?? '0'), count: BigInt(j.count ?? '0') };
    } catch {
      // Never read a corrupt tally as zero - that silently discards fees already owed.
      throw new Error(`x402 fee tally is unreadable: ${path}. Refusing to treat it as zero.`);
    }
  };

  const write = (v: { accrued: bigint; count: bigint }): void => {
    const tmp = path + '.tmp';
    writeFileSync(tmp, JSON.stringify({
      accruedScaled: v.accrued.toString(), count: v.count.toString(),
      updated: new Date().toISOString(),
    }));
    renameSync(tmp, path);
  };

  async function withLock<T>(fn: () => T): Promise<T> {
    const deadline = Date.now() + timeout;
    let fd: number | undefined;
    for (;;) {
      try { fd = openSync(lockPath, 'wx'); break; }        // O_CREAT|O_EXCL - one winner
      catch {
        if (Date.now() > deadline) throw new Error(`x402 fee lock timed out: ${lockPath}`);
        await sleep(15);
      }
    }
    try { return fn(); }
    finally {
      try { closeSync(fd!); } catch { /* already closed */ }
      try { unlinkSync(lockPath); } catch { /* already gone */ }
    }
  }

  return {
    get: async () => withLock(read),
    set: async (v: { accrued: bigint; count: bigint }) => { await withLock(() => write(v)); },
    /**
     * Read, modify and write while HOLDING the lock. Separate get/set calls each take the
     * lock and release it, so two processes can both read the same count and both write
     * count+1 - one increment vanishes. Measured at 82% loss with eight concurrent writers,
     * which shows up as the fee firing far less often than it is owed.
     */
    update: async (fn: (cur: { accrued: bigint; count: bigint }) => { accrued: bigint; count: bigint }) =>
      withLock(() => { const next = fn(read()); write(next); return next; }),
  };
}

/**
 * File-backed collector queue. Node-only. Keeps pending authorizations and the set of
 * nonces ever seen, so a replay is rejected even across restarts.
 */
export function createFileCollectorStore(path: string) {
  const read = () => {
    if (!existsSync(path)) return { pending: [] as any[], seen: [] as string[] };
    try { return JSON.parse(readFileSync(path, 'utf8')); }
    catch {
      // Reading a corrupt queue as empty would forget owed fees AND re-open replay.
      throw new Error(`x402 collector store is unreadable: ${path}. Refusing to treat it as empty.`);
    }
  };
  const write = (d: any) => {
    const tmp = path + '.tmp';
    writeFileSync(tmp, JSON.stringify(d));
    renameSync(tmp, path);
  };
  return {
    pending: async () => read().pending ?? [],
    add: async (item: any) => { const d = read(); d.pending = [...(d.pending ?? []), item]; write(d); },
    remove: async (nonces: string[]) => {
      const d = read();
      const drop = new Set(nonces.map(n => n.toLowerCase()));
      d.pending = (d.pending ?? []).filter((i: any) => !drop.has(i.authorization.nonce.toLowerCase()));
      write(d);
    },
    seen: async (nonce: string) => (read().seen ?? []).includes(nonce.toLowerCase()),
    markSeen: async (nonce: string) => {
      const d = read();
      d.seen = [...(d.seen ?? []), nonce.toLowerCase()];
      write(d);
    },
  };
}

/**
 * File-backed replay guard for the seller. Node-only.
 *
 * Remembers each settled authorization nonce only until it expires - after `validBefore`
 * the authorization can never settle again, so the entry is prunable. Without that, a
 * long-running seller's guard grows forever.
 */
export function createFileNonceStore(path: string) {
  const read = (): Record<string, number> => {
    if (!existsSync(path)) return {};
    try { return JSON.parse(readFileSync(path, 'utf8')).nonces ?? {}; }
    catch {
      // Reading a corrupt guard as empty would re-open replay of every settled payment.
      throw new Error(`x402 nonce store is unreadable: ${path}. Refusing to treat it as empty.`);
    }
  };
  const write = (n: Record<string, number>) => {
    const tmp = path + '.tmp';
    writeFileSync(tmp, JSON.stringify({ nonces: n, updated: new Date().toISOString() }));
    renameSync(tmp, path);
  };
  return {
    seen: async (nonce: string): Promise<boolean> => {
      const now = Math.floor(Date.now() / 1000);
      const exp = read()[nonce.toLowerCase()];
      return exp !== undefined && exp > now;
    },
    add: async (nonce: string, expiresAtUnix: number): Promise<void> => {
      const now = Math.floor(Date.now() / 1000);
      const n = read();
      for (const [k, exp] of Object.entries(n)) if (exp <= now) delete n[k];   // prune
      n[nonce.toLowerCase()] = expiresAtUnix;
      write(n);
    },
    /** Entries currently held (after pruning expired ones). */
    size: (): number => {
      const now = Math.floor(Date.now() / 1000);
      return Object.values(read()).filter(e => e > now).length;
    },
  };
}
