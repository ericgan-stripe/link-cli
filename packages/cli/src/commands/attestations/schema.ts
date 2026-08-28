import { z } from 'incur';
import { DEFAULT_AAT_POOL_PATH } from './pool';

export const requestOptions = z.object({
  count: z.coerce
    .number()
    .int()
    .positive()
    .max(100)
    .describe('Number of tokens to request'),
  issuer: z
    .string()
    .default('https://api.link.com')
    .describe('Link origin that attests to your agent'),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Access token. Defaults to the stored credentials from "link-cli auth login".',
    ),
  poolFile: z
    .string()
    .default(DEFAULT_AAT_POOL_PATH)
    .describe(
      'Local file that stores unused attestation tokens for identity request. Created if missing.',
    ),
});
