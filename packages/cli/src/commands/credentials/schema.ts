import { homedir } from 'node:os';
import { join } from 'node:path';
import { z } from 'incur';

export const issueOptions = z.object({
  keyFile: z
    .string()
    .default(join(homedir(), '.link', 'holder-key.jwk'))
    .describe(
      'Path to the holder private key (JWK). Generated with 0600 permissions if it does not exist. The credential is bound to this key, so reuse the same file to present it later.',
    ),
  keyType: z
    .enum(['ed25519', 'p256'])
    .default('ed25519')
    .describe(
      'Holder key type to generate when --key-file does not exist yet: ed25519 (EdDSA) or p256 (ES256). Ignored when the file already exists.',
    ),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Bearer token for the issuer (needs the aap:represent, userinfo:read and payment_methods.agentic scopes). Defaults to the stored credentials from "link-cli auth login".',
    ),
});
