import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IAttestationsResource } from '@stripe/link-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { remainingCount } from '../attestations/pool';
import { base64urlPad } from '../request/private-token';
import { createMppIdentityProvider } from './identity';

function stableChallenge(issuerName: string): Buffer {
  const issuer = Buffer.from(issuerName);
  const challenge = Buffer.alloc(2 + 2 + issuer.length + 1 + 2);
  challenge.writeUInt16BE(0x0002, 0);
  challenge.writeUInt16BE(issuer.length, 2);
  issuer.copy(challenge, 4);
  return challenge;
}

function token(challengeDigest: Buffer, tokenKeyId: Buffer): string {
  const bytes = Buffer.alloc(2 + 32 + 32 + 32 + 8);
  bytes.writeUInt16BE(0x0002, 0);
  challengeDigest.copy(bytes, 34);
  tokenKeyId.copy(bytes, 66);
  return bytes.toString('base64url');
}

describe('MPP identity provider', () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('automatically refills an empty attestation pool', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-mpp-identity-'));
    directories.push(directory);
    const poolFile = join(directory, 'aat-pool.json');
    const challenge = stableChallenge('api.link.com');
    const challengeDigest = createHash('sha256').update(challenge).digest();
    const tokenKey = Buffer.alloc(32, 7);
    const tokenKeyId = createHash('sha256').update(tokenKey).digest();
    const issued = {
      issuer: 'https://api.link.com',
      token_key_id: tokenKeyId.toString('base64url'),
      tokens: Array.from({ length: 10 }, () =>
        token(challengeDigest, tokenKeyId),
      ),
    };
    const request = vi.fn(async () => issued);
    const provider = createMppIdentityProvider({
      url: 'https://merchant.example/pay',
      resources: {
        poolFile,
        keyFile: join(directory, 'holder-key.jwk'),
        createAttestationsResource: () =>
          ({ request }) as unknown as IAttestationsResource,
        createCredentialsResource: () => {
          throw new Error('claims should not be requested');
        },
      },
    });

    const prepared = await provider.prepare(
      response(401, {
        'WWW-Authenticate': `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}"`,
      }),
    );

    expect(request).toHaveBeenCalledWith({
      issuer: 'https://api.link.com',
      count: 10,
    });
    expect(prepared?.attestation).toMatch(/^PrivateToken token=/);
    expect(remainingCount(poolFile)).toBe(9);
  });
});

function response(status: number, headers: Record<string, string>) {
  return new Response('{}', { status, headers });
}
