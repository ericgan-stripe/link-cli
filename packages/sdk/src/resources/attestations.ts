import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import type { LinkOptions } from '@/config';
import {
  LinkApiError,
  LinkConfigurationError,
  LinkResponseError,
  LinkTransportError,
} from '@/errors';
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
const CONTENT_TYPE_TOKEN_REQUEST = 'application/private-token-request';
const CONTENT_TYPE_TOKEN_RESPONSE = 'application/private-token-response';

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
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(vector.length, 0);
  return Buffer.concat([prefix, vector]);
}

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

  const vectorLength = body.readUInt16BE(0);
  const vector = body.subarray(2);
  if (vector.length !== vectorLength) {
    throw new Error(
      `BatchTokenResponse length prefix says ${vectorLength} bytes but ${vector.length} bytes follow`,
    );
  }
  if (vectorLength === 0 || vectorLength % elementSize !== 0) {
    throw new Error(
      `BatchTokenResponse vector of ${vectorLength} bytes is not a multiple of the ${elementSize}-byte element size`,
    );
  }

  const count = vectorLength / elementSize;
  if (count !== expectedCount) {
    throw new Error(
      `Issuer returned ${count} blind signatures for ${expectedCount} token requests`,
    );
  }

  return Array.from({ length: count }, (_, index) =>
    base64urlEncode(
      new Uint8Array(
        vector.subarray(index * elementSize, (index + 1) * elementSize),
      ),
    ),
  );
}

function parseIssuerOrigin(issuer: string): URL {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch (error) {
    throw new LinkConfigurationError(`Invalid issuer URL: ${issuer}`, {
      cause: error,
    });
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    isIP(hostname) !== 0
  ) {
    throw new LinkConfigurationError(
      'Issuer must be an HTTPS origin with a DNS hostname',
    );
  }
  return url;
}

function requireIssuerEndpoint(
  value: string,
  issuerOrigin: string,
  field: string,
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new TypeError(`${field} is not a valid URL`, { cause: error });
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (
    url.protocol !== 'https:' ||
    url.origin !== issuerOrigin ||
    url.username ||
    url.password ||
    isIP(hostname) !== 0
  ) {
    throw new TypeError(`${field} must be an HTTPS URL on the issuer origin`);
  }
  return url.href;
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
