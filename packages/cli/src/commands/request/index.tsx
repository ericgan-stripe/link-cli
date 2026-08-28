import type {
  ICredentialsResource,
  IWebBotAuthResource,
} from '@stripe/link-sdk';
import { Cli } from 'incur';
import type { CliAuthStorage } from '../../auth/storage';
import { requireAuthGuard } from '../../utils/require-auth';
import { sanitizeDeep } from '../../utils/sanitize-text';
import { requestArgs, requestOptions } from './schema';

function parseBody(body: string): unknown {
  try {
    return sanitizeDeep(JSON.parse(body));
  } catch {
    return sanitizeDeep(body);
  }
}

export function createRequestCli(
  createCredentialsResource: () => ICredentialsResource,
  createWebBotAuthResource: () => IWebBotAuthResource,
  authStorage?: CliAuthStorage,
  envAccessToken?: string,
) {
  return Cli.create('request', {
    description:
      'Make an HTTPS request. If the site asks who you are, present signed user info from Link.',
    args: requestArgs,
    options: requestOptions,
    alias: { method: 'X', data: 'd', header: 'H' },
    mcp: false,
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
        claimReferenceKey,
        contentDigest,
        formatClaimReference,
        parseClaimList,
        parseClaimsChallenge,
        setRequestHeader,
        supportsPreProvisionedPresentation,
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
        return c.error({
          code: 'INVALID_INPUT',
          message:
            error instanceof TypeError
              ? `Invalid URL: ${url}`
              : (error as Error).message,
        });
      }
      const send = (requestHeaders: Record<string, string>) =>
        fetch(url, {
          method: httpMethod,
          body: data,
          headers: requestHeaders,
          redirect: 'manual',
        });

      // 1. Try without identity — most requests need nothing more.
      const probe = await send(headers);
      const probeBody = await probe.text();
      let challenge: ReturnType<typeof parseClaimsChallenge>;
      try {
        challenge = parseClaimsChallenge(probe, probeBody);
      } catch (error) {
        return c.error({
          code: 'INVALID_CHALLENGE',
          message: (error as Error).message,
        });
      }

      if (!challenge) {
        return {
          url,
          status: probe.status,
          identity_required: false,
          response: parseBody(probeBody),
        };
      }
      if (challenge.aud !== target.origin) {
        return c.error({
          code: 'INVALID_CHALLENGE',
          message: `Challenge audience ${challenge.aud} does not exactly match ${target.origin}.`,
        });
      }
      if (!supportsPreProvisionedPresentation(challenge)) {
        return c.error({
          code: 'UNSUPPORTED_FORMAT',
          message:
            'The verifier does not accept the supported dc+sd-jwt presentation format.',
        });
      }

      // 2. The server asked who we are. Disclose what it asked for, unless the
      // caller narrowed it with --claims.
      const claimOverride = parseClaimList(claims);
      if (claimOverride) {
        const challenged = new Set(
          challenge.claims.map((claim) => claimReferenceKey(claim)),
        );
        const extra = claimOverride.filter(
          (claim) => !challenged.has(claimReferenceKey(claim)),
        );
        if (extra.length > 0) {
          return c.error({
            code: 'INVALID_INPUT',
            message: `--claims may only narrow the verifier request; not requested: ${extra.map(formatClaimReference).join(', ')}.`,
          });
        }
      }
      const requested = claimOverride ?? challenge.claims;

      const { issueCredential } = await import('../credentials/issue');
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
        return c.error({
          code: 'INVALID_CREDENTIAL',
          message: `Credential returned an invalid issuer: ${credential.issuer}.`,
        });
      }
      if (challenge.trusted_issuers) {
        const trusted = challenge.trusted_issuers.some((issuer) => {
          try {
            return new URL(issuer).origin === credentialIssuerUrl.origin;
          } catch {
            return false;
          }
        });
        if (!trusted) {
          return c.error({
            code: 'UNTRUSTED_ISSUER',
            message: `The credential issuer ${credential.issuer} is not trusted by the verifier.`,
          });
        }
      }

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
          message: `The credential from ${credential.issuer} cannot disclose: ${presented.unavailable.map(formatClaimReference).join(', ')}. It holds: ${Object.keys(credential.claims).join(', ')}.`,
        });
      }

      // 3. Bind the presentation and request body into a request-specific Web
      // Bot Auth HTTP Message Signature, then retry.
      const finalHeaders = { ...headers };
      setRequestHeader(
        finalHeaders,
        'Identity-Presentation',
        presented.presentation,
      );
      if (data !== undefined) {
        setRequestHeader(finalHeaders, 'Content-Digest', contentDigest(data));
      }
      const webBotAuth = await createWebBotAuthResource().signRequest({
        url,
        method: httpMethod,
        headers: finalHeaders,
        ...(data !== undefined ? { body: data } : {}),
      });
      setRequestHeader(finalHeaders, 'Signature', webBotAuth.signature);
      setRequestHeader(
        finalHeaders,
        'Signature-Input',
        webBotAuth.signature_input,
      );
      setRequestHeader(
        finalHeaders,
        'Signature-Agent',
        webBotAuth.signature_agent,
      );
      const final = await send(finalHeaders);
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
          issuer_metadata: new URL(
            '/.well-known/aap-issuer',
            credentialIssuerUrl,
          ).href,
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
