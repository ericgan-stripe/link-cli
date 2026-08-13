import {
  type HolderKeyType,
  type HolderPublicJwk,
  loadOrCreateHolderKey,
} from './holder-key';

interface IssueCredentialResponse {
  credential: string;
  issuer: string;
  expires_at: string;
}

export interface CredentialIssueResult {
  credential: string;
  issuer: string;
  expires_at: string;
  /** Claim names and values recovered from the credential's disclosures. */
  claims: Record<string, unknown>;
  holder_key: {
    path: string;
    created: boolean;
    jwk: HolderPublicJwk;
  };
}

function decodeJsonSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

/**
 * Recovers the disclosed claims from a compact SD-JWT-VC:
 *
 *   <jws>~<disclosure>~...~
 *
 * Each disclosure is base64url(JSON [salt, claim_name, claim_value]).
 */
function decodeDisclosedClaims(credential: string): Record<string, unknown> {
  const [, ...disclosures] = credential.split('~');
  const claims: Record<string, unknown> = {};

  for (const disclosure of disclosures) {
    if (!disclosure) {
      // Trailing separator on a credential with no key-binding JWT.
      continue;
    }
    const parsed = decodeJsonSegment(disclosure);
    if (Array.isArray(parsed) && parsed.length === 3) {
      claims[String(parsed[1])] = parsed[2];
    }
  }

  return claims;
}

export async function issueCredential(options: {
  apiBaseUrl: string;
  keyFile: string;
  keyType: HolderKeyType;
  accessToken?: string;
  getAccessToken?: () => Promise<string>;
}): Promise<CredentialIssueResult> {
  const { apiBaseUrl, keyFile, keyType } = options;

  const holderKey = loadOrCreateHolderKey(keyFile, keyType);

  const token = options.accessToken ?? (await options.getAccessToken?.());
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const url = `${apiBaseUrl.replace(/\/$/, '')}/credentials`;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    // RFC 7800 key confirmation: binds the credential to the holder public key.
    body: JSON.stringify({ cnf: { jwk: holderKey.publicJwk } }),
  });

  if (!res.ok) {
    const body = await res.text();
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `Credential issuance not authorized (${res.status}): ${body}\nLog in with "link-cli auth login" — this endpoint requires the aap:represent, userinfo:read and payment_methods.agentic scopes.`,
      );
    }
    if (res.status === 404) {
      throw new Error(
        `Credential issuance returned 404: ${body}\nThe /credentials endpoint is feature-flagged; it 404s until enabled for this account.`,
      );
    }
    throw new Error(`Credential issuance failed (${res.status}): ${body}`);
  }

  const response: IssueCredentialResponse = await res.json();

  return {
    credential: response.credential,
    issuer: response.issuer,
    expires_at: response.expires_at,
    claims: decodeDisclosedClaims(response.credential),
    holder_key: {
      path: keyFile,
      created: holderKey.created,
      jwk: holderKey.publicJwk,
    },
  };
}
