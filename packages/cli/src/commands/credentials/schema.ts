import { z } from 'incur';
import { DEFAULT_HOLDER_KEY_PATH } from './holder-key';

export const getOptions = z.object({
  keyFile: z
    .string()
    .default(DEFAULT_HOLDER_KEY_PATH)
    .describe(
      'Path to a local key file. Created if missing. Reuse the same file when you present this user info later.',
    ),
  keyType: z
    .enum(['ed25519', 'p256'])
    .default('ed25519')
    .describe(
      'Key type to generate when --key-file does not exist yet. Ignored when the file already exists.',
    ),
  accessToken: z
    .string()
    .optional()
    .describe(
      'Access token. Defaults to the stored credentials from "link-cli auth login".',
    ),
});
