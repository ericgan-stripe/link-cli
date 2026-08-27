import { LinkResponseError } from '@/errors';
import { CredentialsResource } from '@/resources/credentials';
import { describe, expect, it, vi } from 'vitest';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const PUBLIC_JWK = {
  kty: 'OKP' as const,
  crv: 'Ed25519' as const,
  x: 'public-key',
};

describe('CredentialsResource', () => {
  it('issues through the discovered credential endpoint', async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith('/.well-known/aap-issuer')) {
          return jsonResponse({
            issuer: 'https://issuer.example',
            credential_endpoint: 'https://issuer.example/credential',
          });
        }
        expect(url).toBe('https://issuer.example/credential');
        expect(init?.headers).toMatchObject({
          Authorization: 'Bearer access-token',
        });
        expect(JSON.parse(String(init?.body))).toEqual({
          cnf: { jwk: PUBLIC_JWK },
        });
        return jsonResponse({
          credential: 'issuer-jwt~',
          issuer: 'https://issuer.example',
          expires_at: '2026-08-25T00:00:00Z',
        });
      },
    );
    const resource = new CredentialsResource({
      apiBaseUrl: 'https://issuer.example',
      accessToken: 'access-token',
      fetch: fetchMock,
    });

    await expect(
      resource.issue({ cnf: { jwk: PUBLIC_JWK } }),
    ).resolves.toMatchObject({
      credential: 'issuer-jwt~',
      issuer: 'https://issuer.example',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects an off-origin credential endpoint before authentication', async () => {
    const getAccessToken = vi.fn(async () => 'secret');
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({
          issuer: 'https://issuer.example',
          credential_endpoint: 'https://attacker.example/credential',
        }),
    );
    const resource = new CredentialsResource({
      apiBaseUrl: 'https://issuer.example',
      getAccessToken,
      fetch: fetchMock,
    });

    await expect(resource.issue({ cnf: { jwk: PUBLIC_JWK } })).rejects.toThrow(
      'credential_endpoint must be an HTTPS URL',
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it('refuses issuer metadata redirects', async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response('', {
          status: 302,
          headers: { Location: 'https://attacker.example/metadata' },
        }),
    );
    const resource = new CredentialsResource({
      apiBaseUrl: 'https://issuer.example',
      accessToken: 'access-token',
      fetch: fetchMock,
    });

    await expect(resource.issue({ cnf: { jwk: PUBLIC_JWK } })).rejects.toThrow(
      'Refused redirect',
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('wraps malformed credential responses in LinkResponseError', async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) =>
        String(input).endsWith('/.well-known/aap-issuer')
          ? jsonResponse({
              issuer: 'https://issuer.example',
              credential_endpoint: 'https://issuer.example/credential',
            })
          : jsonResponse({ credential: 42 }),
    );
    const resource = new CredentialsResource({
      apiBaseUrl: 'https://issuer.example',
      accessToken: 'access-token',
      fetch: fetchMock,
    });

    await expect(
      resource.issue({ cnf: { jwk: PUBLIC_JWK } }),
    ).rejects.toBeInstanceOf(LinkResponseError);
  });

  it('refreshes LinkOptions authentication after a credential 401', async () => {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, _init?: RequestInit) =>
        String(input).endsWith('/.well-known/aap-issuer')
          ? jsonResponse({
              issuer: 'https://issuer.example',
              credential_endpoint: 'https://issuer.example/credential',
            })
          : jsonResponse({ error: 'unauthorized' }, 401),
    );
    const getAccessToken = vi.fn(
      ({ forceRefresh }: { forceRefresh?: boolean } = {}) =>
        forceRefresh ? 'refreshed-token' : 'initial-token',
    );
    const resource = new CredentialsResource({
      apiBaseUrl: 'https://issuer.example',
      getAccessToken,
      fetch: fetchMock,
    });

    await expect(resource.issue({ cnf: { jwk: PUBLIC_JWK } })).rejects.toThrow(
      'Failed to issue credential (401)',
    );
    expect(getAccessToken).toHaveBeenNthCalledWith(1, undefined);
    expect(getAccessToken).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        Authorization: 'Bearer initial-token',
      }),
    });
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        Authorization: 'Bearer refreshed-token',
      }),
    });
  });
});
