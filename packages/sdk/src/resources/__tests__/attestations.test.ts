import { generateKeyPairSync } from 'node:crypto';
import { LinkResponseError } from '@/errors';
import { AttestationsResource } from '@/resources/attestations';
import { describe, expect, it, vi } from 'vitest';

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('AttestationsResource', () => {
  it('rejects non-HTTPS and IP-literal issuers before fetching', async () => {
    const fetchMock = vi.fn();
    const resource = new AttestationsResource({
      accessToken: 'secret',
      fetch: fetchMock,
    });

    await expect(
      resource.request({ issuer: 'http://127.0.0.1', count: 1 }),
    ).rejects.toThrow('Issuer must be an HTTPS origin with a DNS hostname');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects off-origin metadata before sending the access token', async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({
          issuer: 'https://issuer.example',
          token_issuance_endpoint: 'https://attacker.example/issue',
          token_keys: 'https://issuer.example/token-keys',
        }),
    );
    const resource = new AttestationsResource({
      accessToken: 'secret',
      fetch: fetchMock,
    });

    await expect(
      resource.request({ issuer: 'https://issuer.example', count: 1 }),
    ).rejects.toThrow('token_issuance_endpoint must be an HTTPS URL');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]).toEqual({ redirect: 'manual' });
  });

  it('refuses discovery redirects', async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response('', {
          status: 302,
          headers: { Location: 'https://attacker.example/metadata' },
        }),
    );
    const resource = new AttestationsResource({
      accessToken: 'secret',
      fetch: fetchMock,
    });

    await expect(
      resource.request({ issuer: 'https://issuer.example', count: 1 }),
    ).rejects.toThrow('Refused redirect');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('wraps malformed issuer metadata in LinkResponseError', async () => {
    const resource = new AttestationsResource({
      accessToken: 'secret',
      fetch: vi.fn(async () => jsonResponse({ issuer: 42 })),
    });

    await expect(
      resource.request({ issuer: 'https://issuer.example', count: 1 }),
    ).rejects.toBeInstanceOf(LinkResponseError);
  });

  it('refreshes LinkOptions authentication after an issuance 401', async () => {
    const { publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 1024,
      publicExponent: 0x10001,
    });
    const tokenKey = publicKey
      .export({ format: 'der', type: 'spki' })
      .toString('base64');
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.endsWith('/.well-known/aap-issuer')) {
          return jsonResponse({
            issuer: 'https://issuer.example',
            token_issuance_endpoint: 'https://issuer.example/issue',
            token_keys: 'https://issuer.example/token-keys',
          });
        }
        if (url.endsWith('/token-keys')) {
          return jsonResponse({
            'token-keys': [{ 'token-type': 0x0002, 'token-key': tokenKey }],
          });
        }
        return jsonResponse(
          { error: `unauthorized: ${String(init?.headers)}` },
          401,
        );
      },
    );
    const getAccessToken = vi.fn(
      ({ forceRefresh }: { forceRefresh?: boolean } = {}) =>
        forceRefresh ? 'refreshed-token' : 'initial-token',
    );
    const resource = new AttestationsResource({
      getAccessToken,
      fetch: fetchMock,
    });

    await expect(
      resource.request({ issuer: 'https://issuer.example', count: 1 }),
    ).rejects.toThrow('Failed to issue attestation tokens (401)');

    expect(getAccessToken).toHaveBeenNthCalledWith(1, undefined);
    expect(getAccessToken).toHaveBeenNthCalledWith(2, { forceRefresh: true });
    expect(fetchMock.mock.calls[2]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        Accept: 'application/private-token-generic-batch-response',
        Authorization: 'Bearer initial-token',
        'Content-Type': 'application/private-token-generic-batch-request',
      }),
    });
    const issuanceBody = fetchMock.mock.calls[2]?.[1]?.body;
    expect(issuanceBody).toBeInstanceOf(ArrayBuffer);
    const encodedRequest = Buffer.from(issuanceBody as ArrayBuffer);
    expect(encodedRequest.subarray(0, 2)).toEqual(Buffer.from([0x40, 0x83]));
    expect(encodedRequest.subarray(2, 4)).toEqual(Buffer.from([0x00, 0x02]));
    expect(encodedRequest).toHaveLength(2 + 3 + 128);
    expect(fetchMock.mock.calls[3]?.[1]).toMatchObject({
      headers: expect.objectContaining({
        Authorization: 'Bearer refreshed-token',
      }),
    });
  });

  it('decodes GenericBatchTokenResponse optional entries', async () => {
    const { publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 1024,
      publicExponent: 0x10001,
    });
    const tokenKey = publicKey
      .export({ format: 'der', type: 'spki' })
      .toString('base64');
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith('/.well-known/aap-issuer')) {
        return jsonResponse({
          issuer: 'https://issuer.example',
          token_issuance_endpoint: 'https://issuer.example/issue',
          token_keys: 'https://issuer.example/token-keys',
        });
      }
      if (url.endsWith('/token-keys')) {
        return jsonResponse({
          'token-keys': [{ 'token-type': 0x0002, 'token-key': tokenKey }],
        });
      }
      return new Response(Buffer.from([0x01, 0x00]), {
        status: 200,
        headers: {
          'Content-Type': 'application/private-token-generic-batch-response',
        },
      });
    });
    const resource = new AttestationsResource({
      accessToken: 'secret',
      fetch: fetchMock,
    });

    await expect(
      resource.request({ issuer: 'https://issuer.example', count: 1 }),
    ).rejects.toThrow('Issuer refused token request at index 0');
  });
});
