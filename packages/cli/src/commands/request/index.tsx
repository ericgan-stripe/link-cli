import type { AuthStorage } from '@stripe/link-sdk';
import { Cli } from 'incur';
import { requireAuthGuard } from '../../utils/require-auth';
import { requestArgs, requestOptions } from './schema';

const DEFAULT_API_BASE_URL = 'https://api.link.com';

function parseBody(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

export function createRequestCli(
  getAccessToken?: () => Promise<string>,
  authStorage?: AuthStorage,
  envAccessToken?: string,
) {
  return Cli.create('request', {
    description:
      'Make an HTTP request that satisfies an identity-claims challenge. Sends the request; if the server replies 401 with an AAP claims-required challenge, gets a credential from the Link wallet, presents only the requested claims (see --claims), and retries.',
    args: requestArgs,
    options: requestOptions,
    alias: { method: 'X', data: 'd', header: 'H' },
    // Deliberately not 'agent-only': this is a human-facing command, and that policy
    // suppresses all output on a TTY unless --format is passed explicitly.
    async run(c) {
      // Root commands don't take middleware, so guard inline.
      requireAuthGuard(c, authStorage, envAccessToken);

      const { url } = c.args;
      const { claims, method, data, header, keyFile, keyType } = c.options;

      const {
        buildPresentation,
        buildRequestHeaders,
        parseClaimList,
        parseClaimsChallenge,
      } = await import('./present');

      let headers: Record<string, string>;
      try {
        headers = buildRequestHeaders(data, header);
      } catch (error) {
        return c.error({
          code: 'INVALID_INPUT',
          message: (error as Error).message,
        });
      }

      const httpMethod = method ?? (data !== undefined ? 'POST' : 'GET');
      const send = (extraHeaders: Record<string, string> = {}) =>
        fetch(url, {
          method: httpMethod,
          body: data,
          headers: { ...headers, ...extraHeaders },
        });

      // 1. Try without identity — most requests need nothing more.
      const probe = await send();
      const probeBody = await probe.text();
      const challenge = parseClaimsChallenge(probe.status, probeBody);

      if (!challenge) {
        return {
          url,
          status: probe.status,
          identity_required: false,
          response: parseBody(probeBody),
        };
      }

      // 2. The server asked who we are. Disclose what it asked for, unless the
      // caller narrowed it with --claims.
      const requested = parseClaimList(claims) ?? challenge.claims;

      const { issueCredential } = await import('../credentials/issue');
      const credential = await issueCredential({
        apiBaseUrl: process.env.LINK_API_BASE_URL ?? DEFAULT_API_BASE_URL,
        keyFile,
        keyType,
        getAccessToken,
      });

      const presented = buildPresentation({
        credential: credential.credential,
        keyFile,
        keyType,
        aud: challenge.aud,
        nonce: challenge.nonce,
        disclose: requested,
      });

      if (presented.unavailable.length > 0) {
        return c.error({
          code: 'CLAIMS_UNAVAILABLE',
          message: `The credential from ${credential.issuer} does not contain: ${presented.unavailable.join(', ')}. It holds: ${Object.keys(credential.claims).join(', ')}.`,
        });
      }

      // 3. Retry with the presentation.
      const final = await send({
        'Identity-Presentation': presented.presentation,
      });
      const finalBody = await final.text();

      return {
        url,
        status: final.status,
        identity_required: true,
        challenge: {
          claims: challenge.claims,
          aud: challenge.aud,
          ...(challenge.purpose ? { purpose: challenge.purpose } : {}),
          ...(challenge.trusted_issuers
            ? { trusted_issuers: challenge.trusted_issuers }
            : {}),
        },
        identity: {
          issuer: credential.issuer,
          issuer_metadata: `${credential.issuer}/.well-known/aap-issuer`,
          disclosed: presented.disclosed,
          withheld: presented.withheld,
          credential_expires_at: credential.expires_at,
          holder_key: credential.holder_key.path,
        },
        response: parseBody(finalBody),
      };
    },
  });
}
