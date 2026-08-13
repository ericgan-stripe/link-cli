import { Cli } from 'incur';
import { requestOptions } from './schema';

export function createAttestationsCli(getAccessToken?: () => Promise<string>) {
  const cli = Cli.create('attestations', {
    description: 'Agent Attestation Token (AAT) commands',
  });

  cli.command('request', {
    description:
      'Request attestation tokens from an IDP using the Privacy Pass Blind RSA protocol (RFC 9578 type 0x0002). Returns tokens ready for use in Authorization: PrivateToken headers.',
    options: requestOptions,
    outputPolicy: 'agent-only' as const,
    async run(c) {
      const { count, issuer, targetOrigin, accessToken } = c.options;

      const { requestAttestationTokens } = await import('./request');
      return requestAttestationTokens({
        issuer,
        count,
        targetOrigin,
        accessToken,
        getAccessToken,
      });
    },
  });

  return cli;
}
