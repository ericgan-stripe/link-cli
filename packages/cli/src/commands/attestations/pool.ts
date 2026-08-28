import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const DEFAULT_AAT_POOL_PATH = join(homedir(), '.link', 'aat-pool.json');

const POOL_FILE_MODE = 0o600;

interface PoolBatch {
  issuer: string;
  token_key_id: string;
  tokens: string[];
}

interface PoolFile {
  version: 1;
  batches: PoolBatch[];
}

function emptyPool(): PoolFile {
  return { version: 1, batches: [] };
}

function isPoolFile(value: unknown): value is PoolFile {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (record.version !== 1 || !Array.isArray(record.batches)) {
    return false;
  }
  return record.batches.every((batch) => {
    if (typeof batch !== 'object' || batch === null) {
      return false;
    }
    const entry = batch as Record<string, unknown>;
    return (
      typeof entry.issuer === 'string' &&
      typeof entry.token_key_id === 'string' &&
      Array.isArray(entry.tokens) &&
      entry.tokens.every((token) => typeof token === 'string')
    );
  });
}

export function loadPool(path: string): PoolFile {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!isPoolFile(parsed)) {
      throw new Error(`Attestation pool at ${path} is malformed`);
    }
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return emptyPool();
    }
    throw error;
  }
}

function parsePooledToken(
  token: string,
): { challengeDigest: Buffer; tokenKeyId: Buffer } | null {
  const raw = Buffer.from(token, 'base64url');
  const prefix = 2 + 32 + 32 + 32;
  if (raw.length <= prefix || raw.readUInt16BE(0) !== 0x0002) {
    return null;
  }
  return {
    challengeDigest: raw.subarray(34, 66),
    tokenKeyId: raw.subarray(66, 98),
  };
}

function savePool(path: string, pool: PoolFile): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(pool, null, 2)}\n`, {
    mode: POOL_FILE_MODE,
  });
  chmodSync(path, POOL_FILE_MODE);
}

export function remainingCount(path: string): number {
  return loadPool(path).batches.reduce(
    (total, batch) => total + batch.tokens.length,
    0,
  );
}

export function saveIssuedTokens(
  path: string,
  issuance: { issuer: string; token_key_id: string; tokens: string[] },
): void {
  const pool = loadPool(path);
  const existing = pool.batches.find(
    (batch) =>
      batch.issuer === issuance.issuer &&
      batch.token_key_id === issuance.token_key_id,
  );
  if (existing) {
    existing.tokens.push(...issuance.tokens);
  } else {
    pool.batches.push({
      issuer: issuance.issuer,
      token_key_id: issuance.token_key_id,
      tokens: [...issuance.tokens],
    });
  }
  savePool(path, pool);
}

export function takeMatchingToken(
  path: string,
  match: { challengeDigest: Uint8Array; tokenKeyId?: Uint8Array },
): { token: string; issuer: string; remaining: number } | null {
  const pool = loadPool(path);
  const expectedDigest = Buffer.from(match.challengeDigest);
  const expectedKeyId = match.tokenKeyId
    ? Buffer.from(match.tokenKeyId)
    : undefined;

  for (const batch of pool.batches) {
    if (
      expectedKeyId &&
      Buffer.from(batch.token_key_id, 'base64url').compare(expectedKeyId) !== 0
    ) {
      continue;
    }
    for (let index = 0; index < batch.tokens.length; index++) {
      const token = batch.tokens[index];
      if (token === undefined) {
        continue;
      }
      const parsed = parsePooledToken(token);
      if (!parsed) {
        continue;
      }
      if (parsed.challengeDigest.compare(expectedDigest) !== 0) {
        continue;
      }
      if (expectedKeyId && parsed.tokenKeyId.compare(expectedKeyId) !== 0) {
        continue;
      }
      batch.tokens.splice(index, 1);
      pool.batches = pool.batches.filter((entry) => entry.tokens.length > 0);
      savePool(path, pool);
      return {
        token,
        issuer: batch.issuer,
        remaining: remainingCount(path),
      };
    }
  }
  return null;
}
