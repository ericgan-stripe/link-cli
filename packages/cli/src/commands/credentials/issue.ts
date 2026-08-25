import type { HolderPublicJwk, ICredentialsResource } from '@stripe/link-sdk';
import { type HolderKeyType, loadOrCreateHolderKey } from './holder-key';

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
  resource: ICredentialsResource;
  keyFile: string;
  keyType: HolderKeyType;
}): Promise<CredentialIssueResult> {
  const { resource, keyFile, keyType } = options;

  const holderKey = loadOrCreateHolderKey(keyFile, keyType);
  const response = await resource.issue({
    cnf: { jwk: holderKey.publicJwk },
  });

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
