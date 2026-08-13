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
  targetOrigin: z
    .string()
    .optional()
    .describe(
      'Origin of the service the tokens will be presented to (e.g. http://localhost:3000). Becomes origin_info in the RFC 9577 TokenChallenge. This is the verifier, not the issuer — use --issuer for that.',
    ),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Bearer token for IDP authentication (needs the aap:represent scope). Defaults to the AAP_ACCESS_TOKEN env var, then the stored credentials from "link-cli auth login".',
    ),
});
