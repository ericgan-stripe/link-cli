// Generic yes/no confirmation for command handlers that need to work with
// both interactive terminals and piped stdin.
import {
  type Interface as ReadlineInterface,
  createInterface,
} from 'node:readline';

export interface ConfirmFromStdinOptions {
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
  invalidAnswerMessage?: string;
  nonTtyTimeoutMs?: number;
  promptSuffix?: string;
  readErrorMessage: string;
}

function readAnswerLine(
  readline: ReadlineInterface,
  input: NodeJS.ReadStream,
  readErrorMessage: string,
  nonTtyTimeoutMs: number | undefined,
): Promise<string | null> {
  if (input.readableEnded) {
    return Promise.resolve(null);
  }

  return new Promise((resolve, reject) => {
    const timeout =
      input.isTTY || nonTtyTimeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            cleanup();
            reject(new Error(readErrorMessage));
          }, nonTtyTimeoutMs);

    const cleanup = () => {
      readline.off('line', handleLine);
      readline.off('close', handleClose);
      if (timeout) {
        clearTimeout(timeout);
      }
    };

    const handleClose = () => {
      cleanup();
      resolve(null);
    };

    const handleLine = (line: string) => {
      cleanup();
      resolve(line);
    };

    readline.once('line', handleLine);
    readline.once('close', handleClose);
  });
}

export async function confirmFromStdin(
  message: string,
  options: ConfirmFromStdinOptions,
): Promise<boolean> {
  const {
    input = process.stdin,
    output = process.stderr,
    invalidAnswerMessage = 'Please answer y or n.\n',
    nonTtyTimeoutMs,
    promptSuffix = ' [y/n] ',
    readErrorMessage,
  } = options;

  if (!input.readable) {
    throw new Error(readErrorMessage);
  }

  const readline = createInterface({
    input,
    output,
    terminal: Boolean(input.isTTY && output.isTTY),
  });

  try {
    while (true) {
      output.write(`${message}${promptSuffix}`);
      const line = await readAnswerLine(
        readline,
        input,
        readErrorMessage,
        nonTtyTimeoutMs,
      );
      if (line === null) {
        throw new Error(readErrorMessage);
      }

      const answer = line.trim().toLowerCase();
      if (answer === 'y' || answer === 'yes') {
        return true;
      }

      if (answer === 'n' || answer === 'no') {
        return false;
      }

      output.write(invalidAnswerMessage);
    }
  } finally {
    input.pause();
    readline.close();
  }
}
