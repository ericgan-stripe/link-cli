import type {
  IAttestationsResource,
  ICredentialsResource,
} from '@stripe/link-sdk';
import { Cli } from 'incur';
import { createAttestationsCli } from '../attestations';
import { createCredentialsCli } from '../credentials';

export function createIdentityCli(options: {
  createAttestationsResource: (
    accessToken?: string,
  ) => IAttestationsResource;
  createCredentialsResource: (
    accessToken?: string,
  ) => ICredentialsResource;
}) {
  const cli = Cli.create('identity', {
    description: 'Prove your agent and user identity with Link.',
  });

  cli.command(createAttestationsCli(options.createAttestationsResource));
  cli.command(createCredentialsCli(options.createCredentialsResource));
  return cli;
}
