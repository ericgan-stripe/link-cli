import type {
  ICredentialsResource,
  IWebBotAuthResource,
} from '@stripe/link-sdk';
import { remainingCount, takeMatchingToken } from '../attestations/pool';
import type { HolderKeyType } from '../credentials/holder-key';
import { issueCredential } from '../credentials/issue';
import {
  buildPresentation,
  buildRequestHeaders,
  claimReferenceKey,
  contentDigest,
  formatClaimReference,
  parseClaimList,
  parseClaimsChallenge,
  setRequestHeader,
  supportsPreProvisionedPresentation,
} from './present';
import {
  authorizationHeader,
  parsePrivateTokenChallenges,
} from './private-token';

const MAX_CHALLENGE_ROUNDS = 3;

export type IdentityRequestError = {
  code: string;
  message: string;
};

export type IdentityRequestResult = {
  url: string;
  status: number;
  attestation_required: boolean;
  identity_required: boolean;
  challenge?: {
    claims: unknown;
    aud: string;
    purpose?: string;
    trusted_issuers?: string[];
  };
  attestation?: {
    issuer: string;
    remaining_pool: number;
  };
  identity?: {
    issuer: string;
    issuer_metadata: string;
    disclosed: unknown;
    withheld: unknown;
    credential_expires_at: string;
    holder_key: string;
  };
  prepared_headers?: {
    attestation?: string;
    identity_presentation?: string;
  };
  response: unknown;
};

function parseBody(
  body: string,
  sanitizeDeep: (value: unknown) => unknown,
): unknown {
  try {
    return sanitizeDeep(JSON.parse(body));
  } catch {
    return sanitizeDeep(body);
  }
}

function requestHeader(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  const entry = Object.entries(headers).find(
    ([candidate]) => candidate.toLowerCase() === name.toLowerCase(),
  );
  return entry?.[1];
}

export async function runIdentityRequest(options: {
  url: string;
  claims?: string;
  method?: string;
  data?: string;
  header: string[];
  prepare?: boolean;
  keyFile: string;
  keyType: HolderKeyType;
  poolFile: string;
  createCredentialsResource: () => ICredentialsResource;
  createWebBotAuthResource?: () => IWebBotAuthResource;
  initialResponse?: { response: Response; body: string };
  fetchImpl?: typeof fetch;
  sanitizeDeep: (value: unknown) => unknown;
}): Promise<
  | { ok: true; value: IdentityRequestResult }
  | { ok: false; error: IdentityRequestError }
> {
  const {
    url,
    claims,
    method,
    data,
    header,
    prepare = false,
    keyFile,
    keyType,
    poolFile,
    createCredentialsResource,
    createWebBotAuthResource,
    sanitizeDeep,
  } = options;
  const fetchImpl = options.fetchImpl ?? fetch;

  let headers: Record<string, string>;
  try {
    headers = buildRequestHeaders(data, header);
  } catch (error) {
    return {
      ok: false,
      error: { code: 'INVALID_INPUT', message: (error as Error).message },
    };
  }

  const httpMethod = (
    method ?? (data !== undefined ? 'POST' : 'GET')
  ).toUpperCase();
  let target: URL;
  try {
    target = new URL(url);
    const hostname = target.hostname.replace(/^\[|\]$/g, '');
    const loopback =
      hostname === 'localhost' ||
      hostname === '::1' ||
      hostname.startsWith('127.');
    if (
      (target.protocol !== 'https:' &&
        !(target.protocol === 'http:' && loopback)) ||
      target.username ||
      target.password ||
      target.hash
    ) {
      throw new Error(
        'URL must be HTTPS (HTTP is allowed only for loopback development)',
      );
    }
  } catch (error) {
    return {
      ok: false,
      error: {
        code: 'INVALID_INPUT',
        message:
          error instanceof TypeError
            ? `Invalid URL: ${url}`
            : (error as Error).message,
      },
    };
  }

  const send = (requestHeaders: Record<string, string>) =>
    fetchImpl(url, {
      method: httpMethod,
      body: data,
      headers: requestHeaders,
      redirect: 'manual',
    });

  const originalHeaders = { ...headers };
  let attestation: { issuer: string; remaining_pool: number } | undefined;
  let identity: IdentityRequestResult['identity'];
  let lastChallenge: IdentityRequestResult['challenge'];
  let attestationRequired = false;
  let identityRequired = false;

  for (let round = 0; round <= MAX_CHALLENGE_ROUNDS; round++) {
    const supplied = round === 0 ? options.initialResponse : undefined;
    const response = supplied?.response ?? (await send(headers));
    const body = supplied?.body ?? (await response.text());

    let privateTokenChallenges: ReturnType<typeof parsePrivateTokenChallenges>;
    let claimsChallenge: ReturnType<typeof parseClaimsChallenge>;
    try {
      privateTokenChallenges = parsePrivateTokenChallenges(response);
      claimsChallenge = parseClaimsChallenge(response, body);
    } catch (error) {
      return {
        ok: false,
        error: {
          code: 'INVALID_CHALLENGE',
          message: (error as Error).message,
        },
      };
    }

    if (privateTokenChallenges.length === 0 && !claimsChallenge) {
      return {
        ok: true,
        value: {
          url,
          status: response.status,
          attestation_required: attestationRequired,
          identity_required: identityRequired,
          ...(lastChallenge ? { challenge: lastChallenge } : {}),
          ...(attestation ? { attestation } : {}),
          ...(identity ? { identity } : {}),
          response: parseBody(body, sanitizeDeep),
        },
      };
    }

    if (round === MAX_CHALLENGE_ROUNDS) {
      return {
        ok: false,
        error: {
          code: 'TOO_MANY_CHALLENGES',
          message:
            'The verifier kept challenging after the maximum number of identity retries.',
        },
      };
    }

    const nextHeaders = { ...originalHeaders };

    if (privateTokenChallenges.length > 0) {
      attestationRequired = true;
      const suppliedAttestation = requestHeader(
        originalHeaders,
        'authorization',
      );
      if (suppliedAttestation && /^PrivateToken\s/i.test(suppliedAttestation)) {
        setRequestHeader(nextHeaders, 'Authorization', suppliedAttestation);
      } else {
        const spent =
          privateTokenChallenges
            .map((challenge) =>
              takeMatchingToken(poolFile, {
                challengeDigest: challenge.challengeDigest,
                ...(challenge.tokenKeyId
                  ? { tokenKeyId: challenge.tokenKeyId }
                  : {}),
              }),
            )
            .find((match) => match !== null) ?? null;
        if (!spent) {
          const empty = remainingCount(poolFile) === 0;
          return {
            ok: false,
            error: empty
              ? {
                  code: 'AAT_POOL_EMPTY',
                  message:
                    'No attestation tokens in the local pool. Run "link-cli identity attestations request --count 10" first.',
                }
              : {
                  code: 'AAT_NO_MATCH',
                  message:
                    "The verifier's PrivateToken challenge does not match any token in the local pool.",
                },
          };
        }
        setRequestHeader(
          nextHeaders,
          'Authorization',
          authorizationHeader(spent.token),
        );
        attestation = {
          issuer: spent.issuer,
          remaining_pool: spent.remaining,
        };
      }
    }

    if (claimsChallenge) {
      identityRequired = true;
      if (claimsChallenge.aud !== target.origin) {
        return {
          ok: false,
          error: {
            code: 'INVALID_CHALLENGE',
            message: `Challenge audience ${claimsChallenge.aud} does not exactly match ${target.origin}.`,
          },
        };
      }
      if (!supportsPreProvisionedPresentation(claimsChallenge)) {
        return {
          ok: false,
          error: {
            code: 'UNSUPPORTED_FORMAT',
            message:
              'The verifier does not accept the supported dc+sd-jwt presentation format.',
          },
        };
      }

      const claimOverride = parseClaimList(claims);
      if (claimOverride) {
        const challenged = new Set(
          claimsChallenge.claims.map((claim) => claimReferenceKey(claim)),
        );
        const extra = claimOverride.filter(
          (claim) => !challenged.has(claimReferenceKey(claim)),
        );
        if (extra.length > 0) {
          return {
            ok: false,
            error: {
              code: 'INVALID_INPUT',
              message: `--claims may only narrow the verifier request; not requested: ${extra.map(formatClaimReference).join(', ')}.`,
            },
          };
        }
      }
      const requested = claimOverride ?? claimsChallenge.claims;
      const credential = await issueCredential({
        resource: createCredentialsResource(),
        keyFile,
        keyType,
      });
      let credentialIssuerUrl: URL;
      try {
        credentialIssuerUrl = new URL(credential.issuer);
        if (credentialIssuerUrl.protocol !== 'https:') {
          throw new TypeError('Credential issuer must use HTTPS');
        }
      } catch {
        return {
          ok: false,
          error: {
            code: 'INVALID_CREDENTIAL',
            message: `Credential returned an invalid issuer: ${credential.issuer}.`,
          },
        };
      }
      if (claimsChallenge.trusted_issuers) {
        const trusted = claimsChallenge.trusted_issuers.some((issuer) => {
          try {
            return new URL(issuer).origin === credentialIssuerUrl.origin;
          } catch {
            return false;
          }
        });
        if (!trusted) {
          return {
            ok: false,
            error: {
              code: 'UNTRUSTED_ISSUER',
              message: `The credential issuer ${credential.issuer} is not trusted by the verifier.`,
            },
          };
        }
      }

      const presented = buildPresentation({
        credential: credential.credential,
        keyFile,
        keyType,
        aud: claimsChallenge.aud,
        nonce: claimsChallenge.nonce,
        disclose: requested,
      });
      if (presented.unavailable.length > 0) {
        return {
          ok: false,
          error: {
            code: 'CLAIMS_UNAVAILABLE',
            message: `The credential from ${credential.issuer} cannot disclose: ${presented.unavailable.map(formatClaimReference).join(', ')}. It holds: ${Object.keys(credential.claims).join(', ')}.`,
          },
        };
      }

      setRequestHeader(
        nextHeaders,
        'Identity-Presentation',
        presented.presentation,
      );
      lastChallenge = {
        claims: claimsChallenge.claims,
        aud: claimsChallenge.aud,
        ...(claimsChallenge.purpose
          ? { purpose: claimsChallenge.purpose }
          : {}),
        ...(claimsChallenge.trusted_issuers
          ? { trusted_issuers: claimsChallenge.trusted_issuers }
          : {}),
      };
      identity = {
        issuer: credential.issuer,
        issuer_metadata: new URL('/.well-known/aap-issuer', credentialIssuerUrl)
          .href,
        disclosed: presented.disclosed,
        withheld: presented.withheld,
        credential_expires_at: credential.expires_at,
        holder_key: credential.holder_key.path,
      };
    }

    if (prepare) {
      return {
        ok: true,
        value: {
          url,
          status: response.status,
          attestation_required: attestationRequired,
          identity_required: identityRequired,
          ...(lastChallenge ? { challenge: lastChallenge } : {}),
          ...(attestation ? { attestation } : {}),
          ...(identity ? { identity } : {}),
          prepared_headers: {
            ...(nextHeaders.Authorization
              ? { attestation: nextHeaders.Authorization }
              : {}),
            ...(nextHeaders['Identity-Presentation']
              ? {
                  identity_presentation: nextHeaders['Identity-Presentation'],
                }
              : {}),
          },
          response: parseBody(body, sanitizeDeep),
        },
      };
    }

    if (!createWebBotAuthResource) {
      throw new Error(
        'A Web Bot Auth resource is required when sending an identity request',
      );
    }
    if (data !== undefined) {
      setRequestHeader(nextHeaders, 'Content-Digest', contentDigest(data));
    }
    const webBotAuth = await createWebBotAuthResource().signRequest({
      url,
      method: httpMethod,
      headers: nextHeaders,
      ...(data !== undefined ? { body: data } : {}),
    });
    setRequestHeader(nextHeaders, 'Signature', webBotAuth.signature);
    setRequestHeader(
      nextHeaders,
      'Signature-Input',
      webBotAuth.signature_input,
    );
    setRequestHeader(
      nextHeaders,
      'Signature-Agent',
      webBotAuth.signature_agent,
    );
    headers = nextHeaders;
  }

  return {
    ok: false,
    error: {
      code: 'TOO_MANY_CHALLENGES',
      message:
        'The verifier kept challenging after the maximum number of identity retries.',
    },
  };
}
