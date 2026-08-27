import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildPresentation, parseClaimsChallenge } from './present';

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function digest(disclosure: string, algorithm = 'sha384'): string {
  return createHash(algorithm).update(disclosure).digest('base64url');
}

function issuerJwt(payload: Record<string, unknown>): string {
  return `${encoded({ alg: 'EdDSA' })}.${encoded(payload)}.issuer-signature`;
}

describe('identity presentation', () => {
  const temporaryDirectories: string[] = [];

  afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('requires the complete claims-required challenge envelope', () => {
    const response = {
      status: 401,
      headers: new Headers({
        'WWW-Authenticate': 'Identity-Presentation',
        'Content-Type': 'application/problem+json; charset=utf-8',
      }),
    };

    expect(
      parseClaimsChallenge(
        response,
        JSON.stringify({
          type: 'urn:aap:claims-required',
          aud: 'https://merchant.example',
          nonce: 'single-use',
          claims: ['email', ['address', 'street']],
          formats: ['dc+sd-jwt'],
          trusted_issuers: ['https://issuer.example'],
          purpose: 'Verify\u001b[2J identity',
        }),
      ),
    ).toEqual({
      aud: 'https://merchant.example',
      nonce: 'single-use',
      claims: ['email', ['address', 'street']],
      formats: ['dc+sd-jwt'],
      trusted_issuers: ['https://issuer.example'],
      purpose: 'Verify identity',
    });

    expect(
      parseClaimsChallenge(
        { ...response, headers: new Headers() },
        JSON.stringify({ type: 'urn:aap:claims-required' }),
      ),
    ).toBeNull();
  });

  it('selects nested claim paths and uses the credential _sd_alg', () => {
    const email = encoded(['salt-email', 'email', 'a@example.com']);
    const street = encoded(['salt-street', 'street', 'Main Street']);
    const address = encoded([
      'salt-address',
      'address',
      { _sd: [digest(street)] },
    ]);
    const role0 = encoded(['salt-role-0', { name: 'reader' }]);
    const role1 = encoded(['salt-role-1', { name: 'admin' }]);
    const roles = encoded([
      'salt-roles',
      'roles',
      [{ '...': digest(role0) }, { '...': digest(role1) }],
    ]);
    const jwt = issuerJwt({
      _sd_alg: 'sha-384',
      _sd: [digest(email), digest(address), digest(roles)],
    });
    const credential = [
      jwt,
      email,
      street,
      address,
      role0,
      role1,
      roles,
      '',
    ].join('~');
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-request-'));
    temporaryDirectories.push(directory);

    const result = buildPresentation({
      credential,
      keyFile: join(directory, 'holder.jwk'),
      keyType: 'ed25519',
      aud: 'https://merchant.example',
      nonce: 'single-use',
      disclose: ['email', ['address', 'street'], ['roles', 1, 'name']],
    });

    expect(result.disclosed).toEqual([
      'email',
      ['address', 'street'],
      ['roles', 1, 'name'],
    ]);
    expect(result.unavailable).toEqual([]);
    const parts = result.presentation.split('~');
    expect(parts.slice(1, -1)).toEqual([email, street, address, role1, roles]);
    const sdPart = `${parts.slice(0, -1).join('~')}~`;
    const kbPayload = JSON.parse(
      Buffer.from(parts.at(-1)?.split('.')[1] ?? '', 'base64url').toString(
        'utf8',
      ),
    );
    expect(kbPayload.sd_hash).toBe(
      createHash('sha384').update(sdPart).digest('base64url'),
    );
  });

  it('rejects an unsupported SD-JWT hash algorithm', () => {
    const directory = mkdtempSync(join(tmpdir(), 'link-cli-request-'));
    temporaryDirectories.push(directory);

    expect(() =>
      buildPresentation({
        credential: `${issuerJwt({ _sd_alg: 'md5', _sd: [] })}~`,
        keyFile: join(directory, 'holder.jwk'),
        keyType: 'ed25519',
        aud: 'https://merchant.example',
        nonce: 'single-use',
        disclose: ['email'],
      }),
    ).toThrow('Unsupported SD-JWT hash algorithm');
  });
});
