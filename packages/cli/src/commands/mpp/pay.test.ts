import { afterEach, describe, expect, it, vi } from 'vitest';
import type { MppIdentityProvider } from './pay';
import { payWithSpt } from './pay';

const PAYMENT_CHALLENGE = [
  'Payment id="ch_001",',
  'realm="merchant.example",',
  'method="stripe",',
  'intent="charge",',
  'header="Payment-Authorization",',
  `request="${Buffer.from(
    JSON.stringify({
      networkId: 'net_001',
      amount: '100',
      currency: 'usd',
      decimals: 2,
      paymentMethodTypes: ['card'],
    }),
  ).toString('base64')}",`,
  'expires="2099-01-01T00:00:00Z"',
].join(' ');

function response(status: number, headers?: Record<string, string>) {
  return new Response(status === 200 ? '{"ok":true}' : '{}', {
    status,
    headers,
  });
}

function requestHeaders(call: unknown[] | undefined): Headers {
  const init = call?.[1] as RequestInit;
  return new Headers(init.headers);
}

describe('identity-aware MPP payment', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('negotiates identity and creates a fresh presentation for the paid request', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(401))
      .mockResolvedValueOnce(
        response(402, { 'WWW-Authenticate': PAYMENT_CHALLENGE }),
      )
      .mockResolvedValueOnce(response(401))
      .mockResolvedValueOnce(response(200));
    vi.stubGlobal('fetch', fetchImpl);

    const prepare = vi
      .fn<MppIdentityProvider['prepare']>()
      .mockResolvedValueOnce({
        attestation: 'PrivateToken token="probe-aat"',
        identityPresentation: 'probe-presentation',
      })
      .mockResolvedValueOnce({
        attestation: 'PrivateToken token="paid-aat"',
        identityPresentation: 'paid-presentation',
      });

    const result = await payWithSpt(
      'https://merchant.example/pay',
      'spt_test_123',
      'POST',
      '{"amount":100}',
      undefined,
      { prepare },
    );

    expect(result.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    expect(prepare).toHaveBeenCalledTimes(2);

    const probeHeaders = requestHeaders(fetchImpl.mock.calls[1]);
    expect(probeHeaders.get('authorization')).toBe(
      'PrivateToken token="probe-aat"',
    );
    expect(probeHeaders.get('identity-presentation')).toBe(
      'probe-presentation',
    );

    const freshnessHeaders = requestHeaders(fetchImpl.mock.calls[2]);
    expect(freshnessHeaders.has('authorization')).toBe(false);
    expect(freshnessHeaders.has('payment-authorization')).toBe(false);

    const paidHeaders = requestHeaders(fetchImpl.mock.calls[3]);
    expect(paidHeaders.get('authorization')).toBe(
      'PrivateToken token="paid-aat"',
    );
    expect(paidHeaders.get('identity-presentation')).toBe('paid-presentation');
    expect(paidHeaders.get('payment-authorization')).toMatch(/^Payment /);
    for (const call of fetchImpl.mock.calls) {
      expect((call[1] as RequestInit).redirect).toBe('manual');
    }
  });

  it('keeps the ordinary two-request MPP flow when identity is not required', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        response(402, { 'WWW-Authenticate': PAYMENT_CHALLENGE }),
      )
      .mockResolvedValueOnce(response(200));
    vi.stubGlobal('fetch', fetchImpl);
    const prepare = vi.fn<MppIdentityProvider['prepare']>();

    const result = await payWithSpt(
      'https://merchant.example/pay',
      'spt_test_123',
      'POST',
      '{}',
      undefined,
      { prepare },
    );

    expect(result.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(prepare).not.toHaveBeenCalled();
  });

  it('does not submit the SPT when the fresh identity probe fails', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(401))
      .mockResolvedValueOnce(
        response(402, { 'WWW-Authenticate': PAYMENT_CHALLENGE }),
      )
      .mockResolvedValueOnce(response(503));
    vi.stubGlobal('fetch', fetchImpl);

    const result = await payWithSpt(
      'https://merchant.example/pay',
      'spt_test_123',
      'POST',
      '{}',
      undefined,
      {
        prepare: vi.fn(async () => ({
          attestation: 'PrivateToken token="aat"',
        })),
      },
    );

    expect(result.status).toBe(503);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    for (const call of fetchImpl.mock.calls) {
      expect(requestHeaders(call).has('payment-authorization')).toBe(false);
    }
  });

  it('refuses to overwrite an attestation with a payment credential', async () => {
    const authorizationChallenge = PAYMENT_CHALLENGE.replace(
      'header="Payment-Authorization",',
      '',
    );
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(401))
      .mockResolvedValueOnce(
        response(402, { 'WWW-Authenticate': authorizationChallenge }),
      );
    vi.stubGlobal('fetch', fetchImpl);

    await expect(
      payWithSpt(
        'https://merchant.example/pay',
        'spt_test_123',
        'POST',
        '{}',
        undefined,
        {
          prepare: vi.fn(async () => ({
            attestation: 'PrivateToken token="aat"',
          })),
        },
      ),
    ).rejects.toThrow(/Payment-Authorization/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
