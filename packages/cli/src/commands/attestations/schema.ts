import { z } from 'incur';

export const requestOptions = z.object({
  count: z.coerce
    .number()
    .int()
    .positive()
    .describe('Number of attestation tokens to request'),
  issuer: z
    .string()
    .default('https://idp-puce-theta.vercel.app')
    .describe('Issuer origin URL'),
  origin: z
    .string()
    .optional()
    .describe(
      'Service origin to bind tokens to (used in TokenChallenge construction)',
    ),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Bearer token for IDP authentication (from OAuth flow with aap:represent scope). Falls back to AAP_ACCESS_TOKEN env var.',
    ),
});
