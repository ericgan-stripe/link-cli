import { Cli } from 'incur';
import { issueOptions } from './schema';

const DEFAULT_API_BASE_URL = 'https://api.link.com';

export function createCredentialsCli(getAccessToken?: () => Promise<string>) {
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

      const { issueCredential } = await import('./issue');
      return issueCredential({
        apiBaseUrl: process.env.LINK_API_BASE_URL ?? DEFAULT_API_BASE_URL,
        keyFile,
        keyType,
        accessToken,
        getAccessToken,
      });
    },
  });

  return cli;
}
