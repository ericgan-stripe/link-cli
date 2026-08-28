import type {
  ICredentialsResource,
  IWebBotAuthResource,
} from '@stripe/link-sdk';
import { Cli } from 'incur';
import type { CliAuthStorage } from '../../auth/storage';
import { requireAuthGuard } from '../../utils/require-auth';
import { sanitizeDeep } from '../../utils/sanitize-text';
import { requestArgs, requestOptions } from './schema';

export function createRequestCli(
  createCredentialsResource: () => ICredentialsResource,
  createWebBotAuthResource: () => IWebBotAuthResource,
  authStorage?: CliAuthStorage,
  envAccessToken?: string,
) {
  return Cli.create('request', {
    description:
      'Make an HTTPS request. If the site asks for attestation or who you are, present a Link attestation token and signed user info.',
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
      const { claims, method, data, header, keyFile, keyType, poolFile } =
        c.options;

      const { runIdentityRequest } = await import('./run');
      const result = await runIdentityRequest({
        url,
        claims,
        method,
        data,
        header,
        keyFile,
        keyType,
        poolFile,
        createCredentialsResource,
        createWebBotAuthResource,
        sanitizeDeep,
      });
      if (!result.ok) {
        return c.error(result.error);
      }
      return result.value;
    },
  });
}
