import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { remainingCount, saveIssuedTokens } from '../attestations/pool';
import { base64urlPad } from './private-token';
import { runIdentityRequest } from './run';

function encodeStableTokenChallenge(issuerName: string): Buffer {
  const issuerBytes = Buffer.from(issuerName, 'utf-8');
  const challenge = Buffer.alloc(2 + 2 + issuerBytes.length + 1 + 2);
  challenge.writeUInt16BE(0x0002, 0);
  challenge.writeUInt16BE(issuerBytes.length, 2);
  issuerBytes.copy(challenge, 4);
  challenge.writeUInt8(0, 4 + issuerBytes.length);
  challenge.writeUInt16BE(0, 5 + issuerBytes.length);
  return challenge;
}

function fakeToken(challengeDigest: Buffer, tokenKeyId: Buffer): string {
  const raw = Buffer.alloc(2 + 32 + 32 + 32 + 8);
  raw.writeUInt16BE(0x0002, 0);
  challengeDigest.copy(raw, 34);
  tokenKeyId.copy(raw, 66);
  return raw.toString('base64url');
}

describe('runIdentityRequest PrivateToken retry', () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('spends a pooled token and Web Bot Auth-signs the retry', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-request-'));
    directories.push(directory);
    const poolFile = join(directory, 'aat-pool.json');
    const challenge = encodeStableTokenChallenge('api.link.com');
    const tokenKey = Buffer.alloc(32, 9);
    const digest = createHash('sha256').update(challenge).digest();
    const tokenKeyId = createHash('sha256').update(tokenKey).digest();
    const token = fakeToken(digest, tokenKeyId);
    saveIssuedTokens(poolFile, {
      issuer: 'https://api.link.com',
      token_key_id: tokenKeyId.toString('base64url'),
      tokens: [token],
    });

    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        new Response('attestation required', {
          status: 401,
          headers: {
            'WWW-Authenticate': `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}", max-age=300`,
          },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    const signRequest = vi.fn(async () => ({
      signature: 'agent=:signature:',
      signature_input:
        'agent=("@method" "@authority" "@path" "authorization" "signature-agent");created=1;expires=2;keyid="k";tag="web-bot-auth"',
      signature_agent:
        'https://api.link.com/.well-known/http-message-signatures-directory',
      authority: 'localhost:3000',
      expires_at: '2099-01-01T00:00:00Z',
    }));

    const result = await runIdentityRequest({
      url: 'http://localhost:3000/api/verified/contribute',
      header: [],
      keyFile: join(directory, 'holder.jwk'),
      keyType: 'ed25519',
      poolFile,
      createCredentialsResource: () => {
        throw new Error(
          'should not issue a credential for an AAT-only challenge',
        );
      },
      createWebBotAuthResource: () => ({ signUrl: vi.fn(), signRequest }),
      fetchImpl: fetchImpl as unknown as typeof fetch,
      sanitizeDeep: (value) => value,
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        status: 200,
        attestation_required: true,
        identity_required: false,
        attestation: {
          issuer: 'https://api.link.com',
          remaining_pool: 0,
        },
        response: { ok: true },
      },
    });
    expect(signRequest).toHaveBeenCalledOnce();
    const retry = fetchImpl.mock.calls[1]?.[1] as RequestInit;
    expect((retry.headers as Record<string, string>).Authorization).toMatch(
      /^PrivateToken token="/,
    );
    expect((retry.headers as Record<string, string>).Signature).toBe(
      'agent=:signature:',
    );
  });

  it('prepares an attestation header without sending the retry', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-request-'));
    directories.push(directory);
    const poolFile = join(directory, 'aat-pool.json');
    const challenge = encodeStableTokenChallenge('api.link.com');
    const tokenKey = Buffer.alloc(32, 7);
    const digest = createHash('sha256').update(challenge).digest();
    const tokenKeyId = createHash('sha256').update(tokenKey).digest();
    const token = fakeToken(digest, tokenKeyId);
    saveIssuedTokens(poolFile, {
      issuer: 'https://api.link.com',
      token_key_id: tokenKeyId.toString('base64url'),
      tokens: [token],
    });
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response('attestation required', {
        status: 401,
        headers: {
          'WWW-Authenticate': `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}"`,
        },
      }),
    );

    const result = await runIdentityRequest({
      url: 'http://localhost:3000/api/verified/contribute',
      header: [],
      prepare: true,
      keyFile: join(directory, 'holder.jwk'),
      keyType: 'ed25519',
      poolFile,
      createCredentialsResource: () => {
        throw new Error('should not issue a credential');
      },
      fetchImpl: fetchImpl as unknown as typeof fetch,
      sanitizeDeep: (value) => value,
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        status: 401,
        prepared_headers: {
          attestation: expect.stringMatching(/^PrivateToken token="/),
        },
      },
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('reuses a supplied attestation when preparing a fresh presentation', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-request-'));
    directories.push(directory);
    const poolFile = join(directory, 'aat-pool.json');
    const challenge = encodeStableTokenChallenge('api.link.com');
    const tokenKey = Buffer.alloc(32, 5);
    const digest = createHash('sha256').update(challenge).digest();
    const tokenKeyId = createHash('sha256').update(tokenKey).digest();
    saveIssuedTokens(poolFile, {
      issuer: 'https://api.link.com',
      token_key_id: tokenKeyId.toString('base64url'),
      tokens: [fakeToken(digest, tokenKeyId)],
    });
    const supplied = 'PrivateToken token="already-prepared"';
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response('attestation required', {
        status: 401,
        headers: {
          'WWW-Authenticate': `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}"`,
        },
      }),
    );

    const result = await runIdentityRequest({
      url: 'http://localhost:3000/api/verified/contribute',
      header: [`Authorization: ${supplied}`],
      prepare: true,
      keyFile: join(directory, 'holder.jwk'),
      keyType: 'ed25519',
      poolFile,
      createCredentialsResource: () => {
        throw new Error('should not issue a credential');
      },
      fetchImpl: fetchImpl as unknown as typeof fetch,
      sanitizeDeep: (value) => value,
    });

    expect(result).toMatchObject({
      ok: true,
      value: { prepared_headers: { attestation: supplied } },
    });
    expect(remainingCount(poolFile)).toBe(1);
  });
});
