import { z } from 'incur';

export const requestOptions = z.object({
  count: z.coerce
    .number()
    .int()
    .positive()
    .max(100)
    .describe('Number of attestation tokens to request'),
  issuer: z
    .string()
    .default('https://api.link.com')
    .describe('Issuer origin URL'),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Bearer token for IDP authentication. Defaults to the AAP_ACCESS_TOKEN env var, then the stored credentials from "link-cli auth login".',
    ),
});
