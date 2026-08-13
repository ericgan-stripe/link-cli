import { createHash, createSign, sign as signEd25519 } from 'node:crypto';
import { loadOrCreateHolderKey } from '../credentials/holder-key';
import type { HolderKeyType } from '../credentials/holder-key';

/** The claims-required challenge a verifier returns (AAP Phase 5 "Disclosure"). */
export interface ClaimsChallenge {
  aud: string;
  nonce: string;
  claims: string[];
  purpose?: string;
  trusted_issuers?: string[];
}

const CLAIMS_REQUIRED_TYPE = 'urn:aap:claims-required';

function base64url(input: Buffer | Uint8Array | string): string {
  return Buffer.from(input as Buffer).toString('base64url');
}

function jsonSegment(value: unknown): string {
  return base64url(JSON.stringify(value));
}

/**
 * Recognizes a claims-required challenge. Returns null for any other response so
 * the caller can pass it through untouched.
 */
export function parseClaimsChallenge(
  status: number,
  body: string,
): ClaimsChallenge | null {
  if (status !== 401) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }

  const challenge = parsed as Record<string, unknown>;
  if (challenge.type !== CLAIMS_REQUIRED_TYPE) {
    return null;
  }
  if (
    typeof challenge.aud !== 'string' ||
    typeof challenge.nonce !== 'string'
  ) {
    return null;
  }

  return {
    aud: challenge.aud,
    nonce: challenge.nonce,
    claims: Array.isArray(challenge.claims) ? challenge.claims.map(String) : [],
    ...(typeof challenge.purpose === 'string'
      ? { purpose: challenge.purpose }
      : {}),
    ...(Array.isArray(challenge.trusted_issuers)
      ? { trusted_issuers: challenge.trusted_issuers.map(String) }
      : {}),
  };
}

export interface Presentation {
  presentation: string;
  disclosed: string[];
  withheld: string[];
  /** Claims asked for (or requested via --claims) that the credential doesn't hold. */
  unavailable: string[];
}

function claimNameOf(disclosure: string): string {
  const parsed = JSON.parse(
    Buffer.from(disclosure, 'base64url').toString('utf8'),
  );
  return String(parsed[1]);
}

/**
 * Builds an SD-JWT-VC presentation: the issuer-signed JWT, only the disclosures for
 * `disclose`, and a Key Binding JWT proving possession of the holder key and binding
 * the whole thing to this verifier (`aud`), this challenge (`nonce`), and this exact
 * disclosure set (`sd_hash`).
 */
export function buildPresentation(options: {
  credential: string;
  keyFile: string;
  keyType: HolderKeyType;
  aud: string;
  nonce: string;
  disclose: string[];
}): Presentation {
  const { credential, keyFile, keyType, aud, nonce, disclose } = options;

  const [issuerJwt, ...rest] = credential.split('~');
  const available = rest.filter(Boolean);
  const wanted = new Set(disclose);

  const kept: string[] = [];
  const disclosed: string[] = [];
  const withheld: string[] = [];

  for (const disclosure of available) {
    const name = claimNameOf(disclosure);
    if (wanted.has(name)) {
      kept.push(disclosure);
      disclosed.push(name);
    } else {
      withheld.push(name);
    }
  }

  const unavailable = disclose.filter((name) => !disclosed.includes(name));

  // Everything up to and including the final `~` is what sd_hash covers.
  const sdPart = `${[issuerJwt, ...kept].join('~')}~`;

  const holderKey = loadOrCreateHolderKey(keyFile, keyType);
  const alg = holderKey.type === 'ed25519' ? 'EdDSA' : 'ES256';

  const header = jsonSegment({ typ: 'kb+jwt', alg });
  const payload = jsonSegment({
    aud,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    sd_hash: base64url(createHash('sha256').update(sdPart).digest()),
  });
  const signingInput = Buffer.from(`${header}.${payload}`);

  const signature =
    alg === 'EdDSA'
      ? signEd25519(null, signingInput, holderKey.privateKey)
      : createSign('sha256')
          .update(signingInput)
          // JOSE ES256 wants the raw r‖s pair, not DER.
          .sign({ key: holderKey.privateKey, dsaEncoding: 'ieee-p1363' });

  return {
    presentation: `${sdPart}${header}.${payload}.${base64url(signature)}`,
    disclosed,
    withheld,
    unavailable,
  };
}

export function parseClaimList(claims: string | undefined): string[] | null {
  if (claims === undefined) {
    return null;
  }
  const parsed = claims
    .split(',')
    .map((claim) => claim.trim())
    .filter(Boolean);
  return parsed.length > 0 ? parsed : null;
}

export function buildRequestHeaders(
  data: string | undefined,
  headers: string[],
): Record<string, string> {
  const result: Record<string, string> = {};
  if (data !== undefined) {
    result['Content-Type'] = 'application/json';
  }
  for (const header of headers) {
    const index = header.indexOf(':');
    if (index === -1) {
      throw new Error(`Invalid header "${header}". Use "Name: Value" format.`);
    }
    result[header.slice(0, index).trim()] = header.slice(index + 1).trim();
  }
  return result;
}
