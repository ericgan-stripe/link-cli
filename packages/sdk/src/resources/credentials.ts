import type { LinkOptions } from '@/config';
import { LinkApiError, LinkResponseError, LinkTransportError } from '@/errors';
import {
  parseIssuerOrigin,
  requireIssuerEndpoint,
} from '@/resources/aap-issuer';
import { BaseResource } from '@/resources/base';
import type {
  CredentialIssueParams,
  CredentialIssueResponse,
  ICredentialsResource,
} from '@/resources/interfaces';
import { z } from 'zod';

const credentialIssuerMetadataSchema = z.looseObject({
  issuer: z.string(),
  credential_endpoint: z.string(),
});

const credentialIssueResponseSchema = z.looseObject({
  credential: z.string(),
  issuer: z.string(),
  expires_at: z.string(),
});

export class CredentialsResource
  extends BaseResource
  implements ICredentialsResource
{
  constructor(options: LinkOptions) {
    super(options, '');
  }

  private async discoverCredentialEndpoint(): Promise<string> {
    const issuerUrl = parseIssuerOrigin(this.endpoint);
    const metadataUrl = new URL('/.well-known/aap-issuer', issuerUrl).href;
    let response: Response;
    try {
      response = await this.fetchImpl(metadataUrl, { redirect: 'manual' });
    } catch (error) {
      throw new LinkTransportError(`Request failed: GET ${metadataUrl}`, {
        cause: error,
      });
    }

    const rawBody = await response.text();
    if (response.status >= 300 && response.status < 400) {
      throw new LinkApiError(
        `Refused redirect while fetching issuer metadata (${response.status})`,
        { status: response.status, rawBody },
      );
    }

    let data: unknown = null;
    try {
      data = JSON.parse(rawBody);
    } catch (error) {
      if (response.ok) {
        throw new LinkResponseError('fetch issuer metadata', response.status, {
          cause: error,
        });
      }
    }
    if (!response.ok) {
      this.throwApiError(
        'fetch issuer metadata',
        response.status,
        data,
        rawBody,
      );
    }

    const metadata = this.parseResponse(
      'parse issuer metadata',
      response.status,
      () => credentialIssuerMetadataSchema.parse(data),
    );
    return this.parseResponse(
      'validate issuer metadata',
      response.status,
      () => {
        const metadataIssuerUrl = parseIssuerOrigin(metadata.issuer);
        if (metadataIssuerUrl.origin !== issuerUrl.origin) {
          throw new TypeError(
            'issuer metadata identifier must match the discovery origin',
          );
        }
        return requireIssuerEndpoint(
          metadata.credential_endpoint,
          issuerUrl.origin,
          'credential_endpoint',
        );
      },
    );
  }

  async issue(params: CredentialIssueParams): Promise<CredentialIssueResponse> {
    const endpoint = await this.discoverCredentialEndpoint();
    const send = async (forceRefresh = false): Promise<Response> => {
      const token = await this.getAccessToken(
        forceRefresh ? { forceRefresh: true } : undefined,
      );
      try {
        return await this.fetchImpl(endpoint, {
          method: 'POST',
          redirect: 'manual',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(params),
        });
      } catch (error) {
        throw new LinkTransportError(`Request failed: POST ${endpoint}`, {
          cause: error,
        });
      }
    };

    let response = await send();
    if (response.status === 401 && this.canRefreshAccessToken) {
      response = await send(true);
    }

    const rawBody = await response.text();
    if (response.status >= 300 && response.status < 400) {
      throw new LinkApiError(
        `Refused redirect while issuing credential (${response.status})`,
        { status: response.status, rawBody },
      );
    }

    let data: unknown = null;
    try {
      data = JSON.parse(rawBody);
    } catch (error) {
      if (response.ok) {
        throw new LinkResponseError('issue credential', response.status, {
          cause: error,
        });
      }
    }
    if (!response.ok) {
      this.throwApiError('issue credential', response.status, data, rawBody);
    }

    return this.parseResponse('issue credential', response.status, () =>
      credentialIssueResponseSchema.parse(data),
    );
  }
}
