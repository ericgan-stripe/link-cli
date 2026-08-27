import type { IAttestationsResource } from '@stripe/link-sdk';
import { Cli } from 'incur';
import { requestOptions } from './schema';

export function createAttestationsCli(
  createResource: (accessToken?: string) => IAttestationsResource,
) {
  const cli = Cli.create('attestations', {
    description: 'Agent Attestation Token (AAT) commands',
  });

  cli.command('request', {
    description:
      'Request attestation tokens from an IDP using the Privacy Pass Blind RSA protocol (RFC 9578 type 0x0002). Returns tokens ready for use in Authorization: PrivateToken headers.',
    options: requestOptions,
    outputPolicy: 'agent-only' as const,
    async run(c) {
      const { count, issuer, accessToken } = c.options;

      return createResource(accessToken).request({
        issuer,
        count,
      });
    },
  });

  return cli;
}
