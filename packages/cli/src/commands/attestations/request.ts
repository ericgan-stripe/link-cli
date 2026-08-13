import { createHash } from 'node:crypto';
import {
  type FinalToken,
  base64urlEncode,
  computeChallengeDigest,
  generateBlindedMessages,
  unblindSignatures,
} from './blind-rsa';

// Privacy Pass token type 0x0002: Blind RSA (SHA-384, 2048-bit) per RFC 9578 §8.2.1.
const TOKEN_TYPE_BLIND_RSA = 0x0002;

// RFC 9577 §5 content types for the Privacy Pass issuance protocol.
const CONTENT_TYPE_TOKEN_REQUEST = 'application/private-token-request';
const CONTENT_TYPE_TOKEN_RESPONSE = 'application/private-token-response';

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

/**
 * Encodes a BatchTokenRequest (I-D.ietf-privacypass-batched-tokens §6.3):
 *
 *   struct { uint16 token_type; uint8 truncated_token_key_id; uint8 blinded_msg[Nk]; } TokenRequest;
 *   struct { TokenRequest token_requests<V>; } BatchTokenRequest;  // uint16 byte-length prefix
 */
function encodeBatchTokenRequest(
  blindedMsgs: Uint8Array[],
  truncatedTokenKeyId: number,
): Buffer {
  const entries = blindedMsgs.map((blindedMsg) => {
    const entry = Buffer.alloc(3 + blindedMsg.length);
    entry.writeUInt16BE(TOKEN_TYPE_BLIND_RSA, 0);
    entry.writeUInt8(truncatedTokenKeyId, 2);
    Buffer.from(blindedMsg).copy(entry, 3);
    return entry;
  });

  const vector = Buffer.concat(entries);
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(vector.length, 0);
  return Buffer.concat([prefix, vector]);
}

/**
 * Decodes a BatchTokenResponse (I-D.ietf-privacypass-batched-tokens §6.3):
 *
 *   struct { uint8 blinded_element[Nk]; } TokenResponse;
 *   struct { TokenResponse token_responses<V>; } BatchTokenResponse;  // uint16 byte-length prefix
 */
function decodeBatchTokenResponse(
  body: Buffer,
  elementSize: number,
  expectedCount: number,
): string[] {
  if (body.length < 2) {
    throw new Error(
      `BatchTokenResponse too short: ${body.length} bytes (expected at least 2)`,
    );
  }

  const vectorLen = body.readUInt16BE(0);
  const vector = body.subarray(2);

  if (vector.length !== vectorLen) {
    throw new Error(
      `BatchTokenResponse length prefix says ${vectorLen} bytes but ${vector.length} bytes follow`,
    );
  }
  if (vectorLen === 0 || vectorLen % elementSize !== 0) {
    throw new Error(
      `BatchTokenResponse vector of ${vectorLen} bytes is not a multiple of the ${elementSize}-byte element size`,
    );
  }

  const count = vectorLen / elementSize;
  if (count !== expectedCount) {
    throw new Error(
      `Issuer returned ${count} blind signatures for ${expectedCount} token requests`,
    );
  }

  return Array.from({ length: count }, (_, i) =>
    base64urlEncode(
      new Uint8Array(vector.subarray(i * elementSize, (i + 1) * elementSize)),
    ),
  );
}

export async function requestAttestationTokens(options: {
  issuer: string;
  count: number;
  targetOrigin?: string;
  accessToken?: string;
  getAccessToken?: () => Promise<string>;
}): Promise<AttestationRequestResult> {
  const { issuer, count, targetOrigin } = options;

  // 1. Fetch issuer metadata
  const metadataUrl = `${issuer.replace(/\/$/, '')}/.well-known/aap-issuer`;
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

  const tokenKey = directory['token-keys'].find(
    (k) => k['token-type'] === TOKEN_TYPE_BLIND_RSA,
  );
  if (!tokenKey) {
    throw new Error('No token key with type 0x0002 found in directory');
  }

  // 3. Decode the SPKI public key
  const spkiDer = base64ToBytes(tokenKey['token-key']);

  // 4. Compute challenge digest. origin_info binds the tokens to the service
  // they will be presented to; omitted when no target origin is given.
  const issuerName = new URL(metadata.issuer).hostname;
  const challengeDigest = computeChallengeDigest(
    TOKEN_TYPE_BLIND_RSA,
    issuerName,
    targetOrigin,
  );

  // 5. Generate blinded messages
  const blindingState = generateBlindedMessages(
    spkiDer,
    count,
    challengeDigest,
  );

  // 6. POST the binary BatchTokenRequest to the issuance endpoint.
  // truncated_token_key_id is the last byte of SHA-256(SPKI DER) (RFC 9578 §6.1).
  const tokenKeyIdBytes = new Uint8Array(
    createHash('sha256').update(spkiDer).digest(),
  );
  const truncatedTokenKeyId = tokenKeyIdBytes[tokenKeyIdBytes.length - 1];

  const requestBody = encodeBatchTokenRequest(
    blindingState.tokens.map((t) => t.blindedMsg),
    truncatedTokenKeyId,
  );

  const token =
    options.accessToken ??
    process.env.AAP_ACCESS_TOKEN ??
    (await options.getAccessToken?.());

  const issueHeaders: Record<string, string> = {
    'Content-Type': CONTENT_TYPE_TOKEN_REQUEST,
    Accept: CONTENT_TYPE_TOKEN_RESPONSE,
  };
  if (token) {
    issueHeaders.Authorization = `Bearer ${token}`;
  }

  const issueRes = await fetch(metadata.token_issuance_endpoint, {
    method: 'POST',
    headers: issueHeaders,
    body: new Uint8Array(requestBody),
  });

  if (!issueRes.ok) {
    const body = await issueRes.text();
    if (issueRes.status === 401 || issueRes.status === 403) {
      throw new Error(
        `IDP authentication failed (${issueRes.status}): ${body}\nLog in with "link-cli auth login" (requires the aap:represent scope), or provide a token via --access-token or AAP_ACCESS_TOKEN.`,
      );
    }
    throw new Error(`Token issuance failed (${issueRes.status}): ${body}`);
  }

  // 7. Unblind to get final tokens
  const responseBody = Buffer.from(await issueRes.arrayBuffer());
  const blindSigs = decodeBatchTokenResponse(
    responseBody,
    blindingState.publicKey.nLen,
    count,
  );
  const finalTokens: FinalToken[] = unblindSignatures(blindingState, blindSigs);

  return {
    tokens: finalTokens.map((t) => t.base64url),
    issuer: metadata.issuer,
    token_key_id: base64urlEncode(blindingState.tokenKeyId),
    count: finalTokens.length,
  };
}
