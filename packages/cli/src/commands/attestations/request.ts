import {
  base64urlDecode,
  base64urlEncode,
  computeChallengeDigest,
  generateBlindedMessages,
  unblindSignatures,
  type FinalToken,
} from './blind-rsa';

interface IssuerMetadata {
  issuer: string;
  token_issuance_endpoint: string;
  token_keys: string;
}

interface TokenKeyDirectory {
  'token-keys': Array<{
    'token-type': number;
    'token-key': string;
  }>;
}

interface IssuanceResponse {
  blind_sigs?: string[];
  blind_signatures?: string[];
  token_key_id?: string;
  count?: number;
}

export interface AttestationRequestResult {
  tokens: string[];
  issuer: string;
  token_key_id: string;
  count: number;
}

function base64ToBytes(b64: string): Uint8Array {
  // Handle both standard base64 and base64url
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(normalized, 'base64'));
}

export async function requestAttestationTokens(options: {
  issuer: string;
  count: number;
  origin?: string;
  accessToken?: string;
}): Promise<AttestationRequestResult> {
  const { issuer, count, origin, accessToken } = options;

  // 1. Fetch issuer metadata
  const metadataUrl = `${issuer}/.well-known/agent-attestation`;
  const metaRes = await fetch(metadataUrl);
  if (!metaRes.ok) {
    throw new Error(
      `Failed to fetch issuer metadata from ${metadataUrl}: ${metaRes.status} ${metaRes.statusText}`,
    );
  }
  const metadata: IssuerMetadata = await metaRes.json();

  // 2. Fetch token key directory
  const keysRes = await fetch(metadata.token_keys);
  if (!keysRes.ok) {
    throw new Error(
      `Failed to fetch token keys from ${metadata.token_keys}: ${keysRes.status}`,
    );
  }
  const directory: TokenKeyDirectory = await keysRes.json();

  const tokenKey = directory['token-keys'].find((k) => k['token-type'] === 2);
  if (!tokenKey) {
    throw new Error('No token key with type 0x0002 found in directory');
  }

  // 3. Decode the SPKI public key
  const spkiDer = base64ToBytes(tokenKey['token-key']);

  // 4. Compute challenge digest
  const issuerName = new URL(metadata.issuer).hostname;
  const challengeDigest = computeChallengeDigest(0x0002, issuerName, origin);

  // 5. Generate blinded messages
  const blindingState = generateBlindedMessages(spkiDer, count, challengeDigest);

  // 6. POST to issuance endpoint
  const blindedMsgs = blindingState.tokens.map((t) =>
    base64urlEncode(t.blindedMsg),
  );

  const token = accessToken ?? process.env.AAP_ACCESS_TOKEN;
  const issueHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    issueHeaders.Authorization = `Bearer ${token}`;
  }

  const issueRes = await fetch(metadata.token_issuance_endpoint, {
    method: 'POST',
    headers: issueHeaders,
    body: JSON.stringify({ blinded_msgs: blindedMsgs }),
  });

  if (!issueRes.ok) {
    const body = await issueRes.text();
    if (issueRes.status === 401) {
      throw new Error(
        `IDP authentication failed: ${body}\nProvide a valid token via --access-token or AAP_ACCESS_TOKEN env var (requires OAuth with aap:represent scope from ${issuer}).`,
      );
    }
    throw new Error(
      `Token issuance failed (${issueRes.status}): ${body}`,
    );
  }

  const issuanceResponse: IssuanceResponse = await issueRes.json();

  // Handle both field names (IDP uses blind_sigs, spec says blind_signatures)
  const blindSigs =
    issuanceResponse.blind_signatures ?? issuanceResponse.blind_sigs;
  if (!blindSigs || blindSigs.length === 0) {
    throw new Error(
      'Issuance response missing blind signatures. Response: ' +
        JSON.stringify(issuanceResponse),
    );
  }

  // 7. Unblind to get final tokens
  const finalTokens: FinalToken[] = unblindSignatures(blindingState, blindSigs);

  const tokenKeyId = base64urlEncode(blindingState.tokenKeyId);

  return {
    tokens: finalTokens.map((t) => t.base64url),
    issuer: metadata.issuer,
    token_key_id: tokenKeyId,
    count: finalTokens.length,
  };
}
