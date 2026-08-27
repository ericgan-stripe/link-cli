import { createHash } from 'node:crypto';
import type { LinkOptions } from '@/config';
import {
  LinkApiError,
  LinkConfigurationError,
  LinkResponseError,
  LinkTransportError,
} from '@/errors';
import {
  parseIssuerOrigin,
  requireIssuerEndpoint,
} from '@/resources/issuer-origin';
import {
  type FinalToken,
  base64urlEncode,
  computeChallengeDigest,
  generateBlindedMessages,
  unblindSignatures,
} from '@/resources/attestations-crypto';
import { BaseResource } from '@/resources/base';
import type {
  AttestationRequestParams,
  AttestationRequestResult,
  IAttestationsResource,
} from '@/resources/interfaces';
import { z } from 'zod';

const TOKEN_TYPE_BLIND_RSA = 0x0002;
const CONTENT_TYPE_TOKEN_REQUEST =
  'application/private-token-generic-batch-request';
const CONTENT_TYPE_TOKEN_RESPONSE =
  'application/private-token-generic-batch-response';

const issuerMetadataSchema = z.looseObject({
  issuer: z.string(),
  token_issuance_endpoint: z.string(),
  token_keys: z.string(),
});

const tokenKeyDirectorySchema = z.looseObject({
  'token-keys': z.array(
    z.looseObject({
      'token-type': z.number(),
      'token-key': z.string(),
    }),
  ),
});

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(normalized, 'base64'));
}

function minQuicVarintLength(value: number): 1 | 2 | 4 | 8 {
  if (value < 2 ** 6) return 1;
  if (value < 2 ** 14) return 2;
  if (value < 2 ** 30) return 4;
  return 8;
}

function encodeQuicVarint(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value >= 2 ** 62) {
    throw new Error(`Cannot encode ${value} as a QUIC variable-length integer`);
  }
  const length = minQuicVarintLength(value);
  const encoded = Buffer.alloc(length);
  let remaining = BigInt(value);
  for (let index = length - 1; index >= 0; index--) {
    encoded[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  encoded[0] = encoded[0]! | (Math.log2(length) << 6);
  return encoded;
}

function readQuicVarint(
  body: Buffer,
  offset = 0,
): { value: number; length: number } {
  const first = body[offset];
  if (first === undefined) throw new Error('QUIC varint is absent');
  const length = 1 << (first >> 6);
  if (body.length < offset + length) throw new Error('QUIC varint is truncated');

  let value = BigInt(first & 0x3f);
  for (let index = 1; index < length; index++) {
    value = (value << 8n) | BigInt(body[offset + index]!);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('QUIC varint exceeds the JavaScript safe integer range');
  }
  const numeric = Number(value);
  if (minQuicVarintLength(numeric) !== length) {
    throw new Error('QUIC varint is not minimally encoded');
  }
  return { value: numeric, length };
}

function encodeBatchTokenRequest(
  blindedMessages: Uint8Array[],
  truncatedTokenKeyId: number,
): Buffer {
  const entries = blindedMessages.map((blindedMessage) => {
    const entry = Buffer.alloc(3 + blindedMessage.length);
    entry.writeUInt16BE(TOKEN_TYPE_BLIND_RSA, 0);
    entry.writeUInt8(truncatedTokenKeyId, 2);
    Buffer.from(blindedMessage).copy(entry, 3);
    return entry;
  });

  const vector = Buffer.concat(entries);
  return Buffer.concat([encodeQuicVarint(vector.length), vector]);
}

function decodeBatchTokenResponse(
  body: Buffer,
  elementSize: number,
  expectedCount: number,
): string[] {
  const prefix = readQuicVarint(body);
  const vector = body.subarray(prefix.length);
  if (vector.length !== prefix.value) {
    throw new Error(
      `BatchTokenResponse length prefix says ${prefix.value} bytes but ${vector.length} bytes follow`,
    );
  }
  if (vector.length === 0) throw new Error('BatchTokenResponse vector is empty');

  const signatures: string[] = [];
  let offset = 0;
  while (offset < vector.length) {
    const present = vector[offset++];
    if (present === 0) {
      throw new Error(
        `Issuer refused token request at index ${signatures.length}`,
      );
    }
    if (present !== 1) {
      throw new Error(`Invalid OptionalTokenResponse presence byte ${present}`);
    }
    if (offset + 2 + elementSize > vector.length) {
      throw new Error('Present GenericTokenResponse is truncated');
    }
    const tokenType = vector.readUInt16BE(offset);
    offset += 2;
    if (tokenType !== TOKEN_TYPE_BLIND_RSA) {
      throw new Error(
        `GenericTokenResponse has unsupported token type 0x${tokenType.toString(16).padStart(4, '0')}`,
      );
    }
    signatures.push(
      base64urlEncode(
        new Uint8Array(vector.subarray(offset, offset + elementSize)),
      ),
    );
    offset += elementSize;
  }
  if (signatures.length !== expectedCount) {
    throw new Error(
      `Issuer returned ${signatures.length} token responses for ${expectedCount} token requests`,
    );
  }
  return signatures;
}

export class AttestationsResource
  extends BaseResource
  implements IAttestationsResource
{
  constructor(options: LinkOptions) {
    super(options, '');
  }

  private async fetchJson(
    url: string,
    operation: string,
  ): Promise<{ data: unknown; status: number }> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, { redirect: 'manual' });
    } catch (error) {
      throw new LinkTransportError(`Request failed: GET ${url}`, {
        cause: error,
      });
    }

    const rawBody = await response.text();
    if (response.status >= 300 && response.status < 400) {
      throw new LinkApiError(
        `Refused redirect while attempting to ${operation} (${response.status})`,
        {
          status: response.status,
          rawBody,
        },
      );
    }
    let data: unknown = null;
    try {
      data = JSON.parse(rawBody);
    } catch (error) {
      if (response.ok) {
        throw new LinkResponseError(operation, response.status, {
          cause: error,
        });
      }
    }

    if (!response.ok) {
      throw new LinkApiError(
        `Failed to ${operation} (${response.status}): ${rawBody}`,
        {
          status: response.status,
          rawBody,
          details: data,
        },
      );
    }
    return { data, status: response.status };
  }

  private async issueTokens(
    url: string,
    body: Uint8Array,
    forceRefresh = false,
  ): Promise<Response> {
    const token = await this.getAccessToken(
      forceRefresh ? { forceRefresh: true } : undefined,
    );
    const requestBody = new ArrayBuffer(body.byteLength);
    new Uint8Array(requestBody).set(body);
    try {
      return await this.fetchImpl(url, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          'Content-Type': CONTENT_TYPE_TOKEN_REQUEST,
          Accept: CONTENT_TYPE_TOKEN_RESPONSE,
          Authorization: `Bearer ${token}`,
        },
        body: requestBody,
      });
    } catch (error) {
      throw new LinkTransportError(`Request failed: POST ${url}`, {
        cause: error,
      });
    }
  }

  async request(
    params: AttestationRequestParams,
  ): Promise<AttestationRequestResult> {
    const { issuer, count } = params;
    if (!Number.isInteger(count) || count < 1 || count > 100) {
      throw new LinkConfigurationError(
        'Attestation token count must be an integer from 1 to 100',
      );
    }
    const issuerUrl = parseIssuerOrigin(issuer);
    const metadataUrl = new URL('/.well-known/aap-issuer', issuerUrl).href;
    const metadataResponse = await this.fetchJson(
      metadataUrl,
      'fetch issuer metadata',
    );
    const metadata = this.parseResponse(
      'parse issuer metadata',
      metadataResponse.status,
      () => issuerMetadataSchema.parse(metadataResponse.data),
    );
    let tokenKeysUrl: string;
    let issuanceUrl: string;
    try {
      const metadataIssuerUrl = parseIssuerOrigin(metadata.issuer);
      if (metadataIssuerUrl.origin !== issuerUrl.origin) {
        throw new TypeError(
          'issuer metadata identifier must match the discovery origin',
        );
      }
      tokenKeysUrl = requireIssuerEndpoint(
        metadata.token_keys,
        issuerUrl.origin,
        'token_keys',
      );
      issuanceUrl = requireIssuerEndpoint(
        metadata.token_issuance_endpoint,
        issuerUrl.origin,
        'token_issuance_endpoint',
      );
    } catch (error) {
      throw new LinkResponseError(
        'validate issuer metadata',
        metadataResponse.status,
        { cause: error },
      );
    }
    const directoryResponse = await this.fetchJson(
      tokenKeysUrl,
      'fetch token keys',
    );
    const directory = this.parseResponse(
      'parse token key directory',
      directoryResponse.status,
      () => tokenKeyDirectorySchema.parse(directoryResponse.data),
    );
    const tokenKey = directory['token-keys'].find(
      (entry) => entry['token-type'] === TOKEN_TYPE_BLIND_RSA,
    );
    if (!tokenKey) {
      throw new LinkResponseError(
        'select Blind RSA token key',
        directoryResponse.status,
        {
          cause: new Error('No token key with type 0x0002 found in directory'),
        },
      );
    }

    const spkiDer = base64ToBytes(tokenKey['token-key']);
    const challengeDigest = computeChallengeDigest(
      TOKEN_TYPE_BLIND_RSA,
      new URL(metadata.issuer).hostname,
    );
    const blindingState = generateBlindedMessages(
      spkiDer,
      count,
      challengeDigest,
    );
    const tokenKeyIdBytes = new Uint8Array(
      createHash('sha256').update(spkiDer).digest(),
    );
    const truncatedTokenKeyId = tokenKeyIdBytes.at(-1);
    if (truncatedTokenKeyId === undefined) {
      throw new LinkResponseError('derive Blind RSA token key ID', 200);
    }
    const requestBody = encodeBatchTokenRequest(
      blindingState.tokens.map((token) => token.blindedMsg),
      truncatedTokenKeyId,
    );

    let issueResponse = await this.issueTokens(
      issuanceUrl,
      new Uint8Array(requestBody),
    );
    if (issueResponse.status === 401 && this.canRefreshAccessToken) {
      issueResponse = await this.issueTokens(
        issuanceUrl,
        new Uint8Array(requestBody),
        true,
      );
    }

    if (!issueResponse.ok) {
      const rawBody = await issueResponse.text();
      throw new LinkApiError(
        `Failed to issue attestation tokens (${issueResponse.status}): ${rawBody}`,
        {
          status: issueResponse.status,
          rawBody,
        },
      );
    }

    let blindSignatures: string[];
    try {
      blindSignatures = decodeBatchTokenResponse(
        Buffer.from(await issueResponse.arrayBuffer()),
        blindingState.publicKey.nLen,
        count,
      );
    } catch (error) {
      throw new LinkResponseError(
        'decode attestation token response',
        issueResponse.status,
        { cause: error },
      );
    }
    const finalTokens: FinalToken[] = unblindSignatures(
      blindingState,
      blindSignatures,
    );

    return {
      tokens: finalTokens.map((finalToken) => finalToken.base64url),
      issuer: metadata.issuer,
      token_key_id: base64urlEncode(blindingState.tokenKeyId),
      count: finalTokens.length,
    };
  }
}
