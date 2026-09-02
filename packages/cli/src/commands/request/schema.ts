import { z } from 'incur';
import { DEFAULT_AAT_POOL_PATH } from '../attestations/pool';
import { DEFAULT_HOLDER_KEY_PATH } from '../credentials/holder-key';

export const requestArgs = z.object({
  url: z
    .string()
    .describe(
      'HTTPS URL to request (HTTP is accepted only for loopback development)',
    ),
});

export const requestOptions = z.object({
  claims: z
    .string()
    .optional()
    .describe(
      'Comma-separated user-info fields to share, e.g. "email,given_name,family_name". Only these are sent. Defaults to what the site asked for.',
    ),
  poolFile: z
    .string()
    .default(DEFAULT_AAT_POOL_PATH)
    .describe(
      'Local file of unused attestation tokens from identity attestations request.',
    ),
  method: z
    .string()
    .optional()
    .describe('HTTP method (default: GET, or POST if --data is provided)'),
  data: z
    .string()
    .optional()
    .describe('Request body (implies POST if --method is not set)'),
  header: z
    .array(z.string())
    .default([])
    .describe('Request header in "Name: Value" format (repeatable)'),
  keyFile: z
    .string()
    .default(DEFAULT_HOLDER_KEY_PATH)
    .describe(
      'Path to a local key file. Created if missing. Reuse the same file used by identity credentials get.',
    ),
  keyType: z
    .enum(['ed25519', 'p256'])
    .default('ed25519')
    .describe(
      'Key type to generate when --key-file does not exist yet. Ignored when it does.',
    ),
});
