import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'incur';

export const requestArgs = z.object({
  url: z.string().describe('URL to request'),
});

export const requestOptions = z.object({
  claims: z
    .string()
    .optional()
    .describe(
      'Comma-separated claims to disclose, e.g. "email,given_name,family_name". Only these are sent, even if the credential holds more. Defaults to exactly what the server asked for.',
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
    .default(join(homedir(), '.link', 'holder-key.jwk'))
    .describe(
      'Path to the holder private key (JWK), generated with 0600 permissions if absent. The credential is bound to this key.',
    ),
  keyType: z
    .enum(['ed25519', 'p256'])
    .default('ed25519')
    .describe(
      'Holder key type to generate when --key-file does not exist yet. Ignored when it does.',
    ),
});
