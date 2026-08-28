import type { ICredentialsResource } from '@stripe/link-sdk';
import { Cli } from 'incur';
import { getOptions } from './schema';

export function createCredentialsCli(
  createResource: (accessToken?: string) => ICredentialsResource,
) {
  const cli = Cli.create('credentials', {
    description:
      'User info that has been signed, proving it comes from Link.',
  });

  cli.command('get', {
    description:
      'Get signed user info proving it comes from Link. Includes a wallet of claims such as name, email, and phone that you can present later.',
    options: getOptions,
    mcp: false,
    outputPolicy: 'agent-only' as const,
    async run(c) {
      const { keyFile, keyType, accessToken } = c.options;

      const { issueCredential } = await import('./issue');
      return issueCredential({
        resource: createResource(accessToken),
        keyFile,
        keyType,
      });
    },
  });

  return cli;
}
