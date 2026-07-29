// Auth-specific yes/no prompt shown during re-login when the requested access
// would remove permissions from the current session.
import {
  type ConfirmFromStdinOptions,
  confirmFromStdin,
} from '../../utils/confirm-stdin';

const NON_TTY_PROMPT_TIMEOUT_MS = 5_000;
const STDIN_CONFIRMATION_ERROR =
  'Could not read a yes/no answer from stdin. Pipe "y" or "n" into the command and try again.';

type ConfirmLoginAccessOptions = Pick<
  ConfirmFromStdinOptions,
  'input' | 'output'
>;

export async function confirmLoginAccess(
  message: string,
  options: ConfirmLoginAccessOptions = {},
): Promise<boolean> {
  return confirmFromStdin(message, {
    ...options,
    nonTtyTimeoutMs: NON_TTY_PROMPT_TIMEOUT_MS,
    readErrorMessage: STDIN_CONFIRMATION_ERROR,
  });
}
