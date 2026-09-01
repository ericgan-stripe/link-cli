import type {
  IPaymentMethodsResource,
  ISpendRequestResource,
} from '@stripe/link-sdk';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { Credential, Method } from 'mppx';
import { Mppx, Transport } from 'mppx/client';
import { Methods as StripeMethods } from 'mppx/stripe';
import React, { useEffect, useState } from 'react';
import { pollUntilApproved } from '../../utils/poll-until-approved';
import { sanitizeDeep } from '../../utils/sanitize-text';
import {
  DEFAULT_CREDENTIAL_HEADER,
  PAYMENT_AUTHORIZATION_HEADER,
  type PaymentCredentialHeader,
  canonicalizeCredentialHeader,
} from './credential-header';
import {
  decodeStripeChallenge,
  getStripeChargeChallengeFromResponse,
} from './decode';

export type PayResult = {
  status: number;
  headers: Record<string, string>;
  body: string;
};

export interface MppIdentityHeaders {
  attestation?: string;
  identityPresentation?: string;
}

export interface MppIdentityProvider {
  prepare(response: Response): Promise<MppIdentityHeaders | undefined>;
}

export function buildHeaders(
  data: string | undefined,
  headers: string[] | undefined,
): Record<string, string> {
  const result: Record<string, string> = {};
  if (data !== undefined) {
    result['Content-Type'] = 'application/json';
  }
  for (const line of headers ?? []) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key) result[key] = value;
  }
  return result;
}

export async function readPayResult(response: Response): Promise<PayResult> {
  const responseHeaders = Object.fromEntries(response.headers.entries());
  const body = await response.text();
  // Response body and headers are fully attacker-controlled. Strip ANSI escape
  // sequences and control characters so they cannot spoof the terminal UI or
  // inject content into the agent's context. See CLAUDE.md security note.
  return sanitizeDeep({
    status: response.status,
    headers: responseHeaders,
    body,
  });
}

function setPaymentCredential(
  headers: Headers,
  credentialHeader: PaymentCredentialHeader,
  credential: string,
): void {
  if (credentialHeader === PAYMENT_AUTHORIZATION_HEADER) {
    headers.set(PAYMENT_AUTHORIZATION_HEADER, credential);
    return;
  }
  headers.set(DEFAULT_CREDENTIAL_HEADER, credential);
}

function setIdentityHeaders(
  headers: Headers,
  identity: MppIdentityHeaders | undefined,
): void {
  if (!identity) return;
  if (identity.attestation) {
    headers.set('Authorization', identity.attestation);
  }
  if (identity.identityPresentation) {
    headers.set('Identity-Presentation', identity.identityPresentation);
  }
}

export function buildMppHeaders(
  data: string | undefined,
  headers: string[] | undefined,
  identity: MppIdentityHeaders | undefined,
): Headers {
  const result = new Headers(buildHeaders(data, headers));
  setIdentityHeaders(result, identity);
  return result;
}
function createStripePaymentClient(spt: string) {
  const stripeCharge = Method.toClient(StripeMethods.charge, {
    async createCredential({ challenge }) {
      canonicalizeCredentialHeader(challenge.header);
      return Credential.serialize({
        challenge,
        payload: { spt },
      });
    },
  });

  const stripeSession = Method.toClient(
    { ...StripeMethods.charge, intent: 'session' as const },
    {
      async createCredential({ challenge }) {
        canonicalizeCredentialHeader(challenge.header);
        return Credential.serialize({
          challenge,
          payload: { action: 'open', grantedToken: spt },
        });
      },
    },
  );

  return Mppx.create({
    methods: [stripeCharge, stripeSession],
    polyfill: false,
    transport: Transport.from<RequestInit, Response>({
      name: 'stripe-http',
      isPaymentRequired(response) {
        return response.status === 402;
      },
      getChallenges(response) {
        return [getStripeChargeChallengeFromResponse(response)];
      },
      setCredential(request, credential, options) {
        const credentialHeader = canonicalizeCredentialHeader(
          options?.challenge?.header,
        );
        const nextHeaders = new Headers(request.headers);
        setPaymentCredential(nextHeaders, credentialHeader, credential);
        return { ...request, headers: nextHeaders };
      },
    }),
  });
}

const MAX_IDENTITY_ROUNDS = 3;

export interface MppPaymentProbe {
  response: Response;
  identityRequired: boolean;
}

async function fetchMerchant(
  url: string,
  method: string,
  data: string | undefined,
  headers: Headers,
): Promise<Response> {
  return fetch(url, {
    method,
    body: data,
    headers,
    // Authorization, identity, and payment credentials must never cross an
    // origin boundary through Fetch's default redirect behavior.
    redirect: 'manual',
  });
}

/** Sends the unpaid request, satisfying any identity challenges before 402. */
export async function probeMppPayment(
  url: string,
  method: string | undefined,
  data: string | undefined,
  headers: string[] | undefined,
  identityProvider?: MppIdentityProvider,
): Promise<MppPaymentProbe> {
  const httpMethod = method ?? (data !== undefined ? 'POST' : 'GET');
  let identity: MppIdentityHeaders | undefined;
  let identityRequired = false;

  for (let round = 0; round <= MAX_IDENTITY_ROUNDS; round++) {
    const response = await fetchMerchant(
      url,
      httpMethod,
      data,
      buildMppHeaders(data, headers, identity),
    );
    if (response.status !== 401 || !identityProvider) {
      return { response, identityRequired };
    }

    const prepared = await identityProvider.prepare(response);
    if (!prepared) return { response, identityRequired };
    if (round === MAX_IDENTITY_ROUNDS) {
      throw new Error(
        'The merchant kept challenging after the maximum number of identity retries.',
      );
    }
    identity = prepared;
    identityRequired = true;
  }

  throw new Error('Identity negotiation did not produce a response');
}

export function paymentChallengeHeader(
  response: Response,
  identityRequired: boolean,
): PaymentCredentialHeader {
  if (!response.headers.has('www-authenticate')) {
    throw new Error('URL returned 402 but no WWW-Authenticate header');
  }
  const challenge = getStripeChargeChallengeFromResponse(response);
  const credentialHeader = canonicalizeCredentialHeader(challenge.header);
  if (identityRequired && credentialHeader !== PAYMENT_AUTHORIZATION_HEADER) {
    throw new Error(
      'Identity-aware MPP requires the payment challenge to advertise header="Payment-Authorization" so the Link attestation can remain in Authorization.',
    );
  }
  return credentialHeader;
}

async function payChallengeWithSpt(
  url: string,
  spt: string,
  method: string | undefined,
  data: string | undefined,
  headers: string[] | undefined,
  probe: MppPaymentProbe,
  identityProvider?: MppIdentityProvider,
): Promise<PayResult> {
  const credentialHeader = paymentChallengeHeader(
    probe.response,
    probe.identityRequired,
  );
  const credential = await createStripePaymentClient(spt).createCredential(
    probe.response,
  );

  let finalIdentity: MppIdentityHeaders | undefined;
  const httpMethod = method ?? (data !== undefined ? 'POST' : 'GET');
  if (probe.identityRequired) {
    if (!identityProvider) {
      throw new Error(
        'Identity was required but no identity provider is available',
      );
    }

    // The presentation used to reach 402 has already spent its nonce. Ask for
    // a fresh challenge, but do not send the resulting presentation until the
    // payment credential is attached to the final request.
    const freshChallenge = await fetchMerchant(
      url,
      httpMethod,
      data,
      buildMppHeaders(data, headers, undefined),
    );
    if (freshChallenge.status === 401) {
      finalIdentity = await identityProvider.prepare(freshChallenge);
      if (!finalIdentity) {
        throw new Error(
          'The merchant required identity but did not return a supported identity challenge for the paid request.',
        );
      }
    } else if (freshChallenge.status !== 402) {
      // Do not send a one-time payment credential after a redirect, transient
      // failure, or successful response that changed the request lifecycle.
      return readPayResult(freshChallenge);
    }
  }

  const finalHeaders = buildMppHeaders(data, headers, finalIdentity);
  setPaymentCredential(finalHeaders, credentialHeader, credential);
  const response = await fetchMerchant(url, httpMethod, data, finalHeaders);
  return readPayResult(response);
}

export interface MppPayFullFlowOptions {
  url: string;
  method: string | undefined;
  data: string | undefined;
  headers: string[] | undefined;
  context: string;
  amountOverride: number | undefined;
  paymentMethodId: string | undefined;
  test: boolean;
  repository: ISpendRequestResource;
  paymentMethodsFactory: () => IPaymentMethodsResource;
  identityProvider?: MppIdentityProvider;
  onStep?: (step: Step) => void;
  onApprovalUrl?: (url: string) => void;
}

export async function runMppPayWithSpendRequest(
  url: string,
  spendRequestId: string,
  method: string | undefined,
  data: string | undefined,
  headers: string[] | undefined,
  repository: ISpendRequestResource,
  identityProvider?: MppIdentityProvider,
): Promise<PayResult> {
  const spendRequest = await repository.retrieve(spendRequestId, {
    include: ['shared_payment_token'],
  });

  if (!spendRequest) {
    throw new Error(`Spend request ${spendRequestId} not found`);
  }
  if (spendRequest.credential_type !== 'shared_payment_token') {
    const type = spendRequest.credential_type ?? 'card';
    throw new Error(
      `Spend request ${spendRequestId} must have credential_type 'shared_payment_token' (current: '${type}')`,
    );
  }
  if (spendRequest.status !== 'approved') {
    throw new Error(
      `Spend request must be approved (current status: ${spendRequest.status})`,
    );
  }
  if (!spendRequest.shared_payment_token) {
    throw new Error('Spend request does not have a shared payment token');
  }

  return payWithSpt(
    url,
    spendRequest.shared_payment_token.id,
    method,
    data,
    headers,
    identityProvider,
  );
}

export async function payWithSpt(
  url: string,
  spt: string,
  method: string | undefined,
  data: string | undefined,
  headers: string[] | undefined,
  identityProvider?: MppIdentityProvider,
): Promise<PayResult> {
  const probe = await probeMppPayment(
    url,
    method,
    data,
    headers,
    identityProvider,
  );
  if (probe.response.status !== 402) return readPayResult(probe.response);
  return payChallengeWithSpt(
    url,
    spt,
    method,
    data,
    headers,
    probe,
    identityProvider,
  );
}

export async function runMppPayFullFlow(
  opts: MppPayFullFlowOptions,
): Promise<PayResult> {
  const {
    url,
    method,
    data,
    headers,
    context,
    amountOverride,
    paymentMethodId,
    test,
    repository,
    paymentMethodsFactory,
    identityProvider,
    onStep,
    onApprovalUrl,
  } = opts;

  // 1. Probe URL
  onStep?.('probing');
  const probe = await probeMppPayment(
    url,
    method,
    data,
    headers,
    identityProvider,
  );
  const probeResponse = probe.response;

  if (probeResponse.status !== 402) {
    return readPayResult(probeResponse);
  }

  // 2. Parse challenge
  const wwwAuth = probeResponse.headers.get('www-authenticate');
  if (!wwwAuth) {
    throw new Error('URL returned 402 but no WWW-Authenticate header');
  }
  paymentChallengeHeader(probeResponse, probe.identityRequired);

  const decoded = decodeStripeChallenge(wwwAuth);
  const networkId = decoded.network_id;
  const challengeAmount = decoded.request_json.amount
    ? Number(decoded.request_json.amount)
    : undefined;
  const challengeCurrency = (decoded.request_json.currency as string) ?? 'usd';

  const amount = amountOverride ?? challengeAmount;
  if (!amount) {
    throw new Error(
      'Could not determine amount from 402 challenge. Pass --amount explicitly.',
    );
  }

  // 3. Get payment method
  let pmId = paymentMethodId;
  if (!pmId) {
    onStep?.('creating');
    const pmResource = paymentMethodsFactory();
    const methods = await pmResource.list();
    if (!methods.length) {
      throw new Error(
        'No payment methods found. Add one with `link-cli payment-methods add`.',
      );
    }
    pmId = methods[0].id;
  }

  // 4. Create spend request
  onStep?.('creating');
  const spendRequest = await repository.create({
    payment_details: pmId,
    credential_type: 'shared_payment_token',
    network_id: networkId,
    amount,
    currency: challengeCurrency,
    context,
    request_approval: true,
    test: test || undefined,
  });

  // 5. Poll for approval
  onStep?.('approving');
  if (spendRequest.approval_url) {
    onApprovalUrl?.(spendRequest.approval_url);
  }

  const approved = await pollUntilApproved(repository, spendRequest.id);
  if (approved.status !== 'approved') {
    throw new Error(
      `Spend request was not approved (status: ${approved.status})`,
    );
  }

  // 6. Retrieve with SPT (retry briefly in case of propagation delay)
  onStep?.('signing');
  let withSpt = await repository.retrieve(spendRequest.id, {
    include: ['shared_payment_token'],
  });
  for (let i = 0; i < 3 && withSpt && !withSpt.shared_payment_token; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    withSpt = await repository.retrieve(spendRequest.id, {
      include: ['shared_payment_token'],
    });
  }
  if (!withSpt?.shared_payment_token) {
    throw new Error('Failed to retrieve shared payment token');
  }

  // 7. Pay
  onStep?.('submitting');
  // Approval can outlive the original payment challenge. Probe again so the
  // one-time SPT is bound to a current challenge, then negotiate a fresh
  // single-use identity presentation for the paid request.
  return payWithSpt(
    url,
    withSpt.shared_payment_token.id,
    method,
    data,
    headers,
    identityProvider,
  );
}

export type Step =
  | 'probing'
  | 'creating'
  | 'approving'
  | 'signing'
  | 'submitting'
  | 'done';

export function MppPay({
  url,
  spendRequestId,
  method,
  data,
  headers,
  context,
  amountOverride,
  paymentMethodId,
  test,
  repository,
  paymentMethodsFactory,
  identityProvider,
  onComplete,
}: {
  url: string;
  spendRequestId?: string;
  method?: string;
  data?: string;
  headers?: string[];
  context?: string;
  amountOverride?: number;
  paymentMethodId?: string;
  test?: boolean;
  repository: ISpendRequestResource;
  paymentMethodsFactory: () => IPaymentMethodsResource;
  identityProvider?: MppIdentityProvider;
  onComplete: (result: PayResult | null) => void;
}) {
  const [step, setStep] = useState<Step>(
    spendRequestId ? 'signing' : 'probing',
  );
  const [result, setResult] = useState<PayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvalUrl, setApprovalUrl] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        let payResult: PayResult;

        if (spendRequestId) {
          setStep('signing');
          payResult = await runMppPayWithSpendRequest(
            url,
            spendRequestId,
            method,
            data,
            headers,
            repository,
            identityProvider,
          );
        } else {
          if (!context) {
            throw new Error(
              '--context is required for the full MPP flow (min 100 chars)',
            );
          }
          payResult = await runMppPayFullFlow({
            url,
            method,
            data,
            headers,
            context,
            amountOverride,
            paymentMethodId,
            test: test ?? false,
            repository,
            paymentMethodsFactory,
            identityProvider,
            onStep: setStep,
            onApprovalUrl: (u) => setApprovalUrl(u),
          });
        }

        setResult(payResult);
        setStep('done');
        onComplete(payResult);
      } catch (err) {
        setError((err as Error).message);
        onComplete(null);
      }
    })();
  }, [
    url,
    spendRequestId,
    method,
    data,
    headers,
    context,
    amountOverride,
    paymentMethodId,
    test,
    repository,
    paymentMethodsFactory,
    identityProvider,
    onComplete,
  ]);

  const stepLabels: Record<Step, string> = {
    probing: 'Probing URL for 402 challenge',
    creating: 'Creating spend request',
    approving: 'Waiting for approval',
    signing: 'Signing credential',
    submitting: 'Submitting payment',
    done: 'Done',
  };

  if (error) {
    return <Text color="red">Error: {error}</Text>;
  }

  return (
    <Box flexDirection="column">
      {step !== 'done' && (
        <Box flexDirection="column">
          <Box>
            <Text color="cyan">
              <Spinner type="dots" /> {stepLabels[step]}...
            </Text>
          </Box>
          {step === 'approving' && approvalUrl && (
            <Box marginTop={1} paddingX={2}>
              <Text>
                Approve in Link app:{' '}
                <Text bold color="blue">
                  {approvalUrl}
                </Text>
              </Text>
            </Box>
          )}
        </Box>
      )}
      {result && (
        <Box flexDirection="column">
          <Text
            color={
              result.status >= 400
                ? 'red'
                : result.status >= 300
                  ? 'yellow'
                  : 'green'
            }
          >
            HTTP {result.status}
          </Text>
          <Text>{result.body}</Text>
        </Box>
      )}
    </Box>
  );
}
