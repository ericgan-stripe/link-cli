import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { remainingCount, saveIssuedTokens, takeMatchingToken } from './pool';

function fakeToken(challengeDigest: Buffer, tokenKeyId: Buffer): string {
  const raw = Buffer.alloc(2 + 32 + 32 + 32 + 8);
  raw.writeUInt16BE(0x0002, 0);
  challengeDigest.copy(raw, 34);
  tokenKeyId.copy(raw, 66);
  return raw.toString('base64url');
}

describe('attestation token pool', () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  function poolPath(): string {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-aat-'));
    directories.push(directory);
    return join(directory, 'aat-pool.json');
  }

  it('appends issued tokens and pops a matching one', () => {
    const path = poolPath();
    const digest = Buffer.alloc(32, 7);
    const keyId = Buffer.alloc(32, 9);
    const first = fakeToken(digest, keyId);
    const second = fakeToken(digest, keyId);

    saveIssuedTokens(path, {
      issuer: 'https://api.link.com',
      token_key_id: keyId.toString('base64url'),
      tokens: [first, second],
    });
    expect(remainingCount(path)).toBe(2);

    const spent = takeMatchingToken(path, {
      challengeDigest: new Uint8Array(digest),
      tokenKeyId: new Uint8Array(keyId),
    });
    expect(spent).toEqual({
      token: first,
      issuer: 'https://api.link.com',
      remaining: 1,
    });
    expect(remainingCount(path)).toBe(1);
  });

  it('returns null when the challenge digest does not match', () => {
    const path = poolPath();
    const digest = Buffer.alloc(32, 1);
    const keyId = Buffer.alloc(32, 2);
    saveIssuedTokens(path, {
      issuer: 'https://api.link.com',
      token_key_id: keyId.toString('base64url'),
      tokens: [fakeToken(digest, keyId)],
    });

    expect(
      takeMatchingToken(path, {
        challengeDigest: new Uint8Array(Buffer.alloc(32, 3)),
        tokenKeyId: new Uint8Array(keyId),
      }),
    ).toBeNull();
    expect(remainingCount(path)).toBe(1);
  });
});
