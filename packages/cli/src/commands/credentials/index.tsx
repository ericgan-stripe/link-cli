import type { ICredentialsResource } from '@stripe/link-sdk';
import { Cli } from 'incur';
import { issueOptions } from './schema';

export function createCredentialsCli(
  createResource: (accessToken?: string) => ICredentialsResource,
) {
  const cli = Cli.create('credentials', {
    description: 'Agent identity credential (SD-JWT-VC) commands',
  });

  cli.command('issue', {
    description:
      "Issue a short-lived SD-JWT-VC holding the user's identity claims (email, phone_number, given_name, family_name), bound to a local holder key. Present selective disclosures from it to merchants.",
    options: issueOptions,
    outputPolicy: 'agent-only' as const,
    async run(c) {
      const { keyFile, keyType, accessToken } = c.options;
      const token = accessToken ?? process.env.AAP_ACCESS_TOKEN;

      const { issueCredential } = await import('./issue');
      return issueCredential({
        resource: createResource(token),
        keyFile,
        keyType,
      });
    },
  });

  return cli;
}
