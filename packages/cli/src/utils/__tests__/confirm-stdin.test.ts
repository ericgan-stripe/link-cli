import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { confirmFromStdin } from '../confirm-stdin';

function createStreams() {
  const input = new PassThrough() as PassThrough & NodeJS.ReadStream;
  const output = new PassThrough() as PassThrough & NodeJS.WriteStream;
  input.isTTY = false;
  output.isTTY = false;

  let written = '';
  output.on('data', (chunk: Buffer | string) => {
    written += chunk.toString();
  });

  return {
    input: input as NodeJS.ReadStream,
    output: output as NodeJS.WriteStream,
    getOutput: () => written,
  };
}

describe('confirmFromStdin', () => {
  it('returns true for yes answers', async () => {
    const { input, output, getOutput } = createStreams();
    const confirmation = confirmFromStdin('Continue?', {
      input,
      output,
      nonTtyTimeoutMs: 50,
      readErrorMessage: 'stdin failed',
    });

    input.end('y\n');

    await expect(confirmation).resolves.toBe(true);
    expect(getOutput()).toContain('Continue? [y/n] ');
  });

  it('re-prompts after an invalid answer and then returns false', async () => {
    const { input, output, getOutput } = createStreams();
    const confirmation = confirmFromStdin('Continue?', {
      input,
      output,
      nonTtyTimeoutMs: 50,
      readErrorMessage: 'stdin failed',
    });

    input.write('maybe\n');
    setTimeout(() => {
      input.end('n\n');
    }, 0);

    await expect(confirmation).resolves.toBe(false);
    expect(getOutput()).toContain('Please answer y or n.');
  });

  it('throws when stdin closes without an answer', async () => {
    const { input, output } = createStreams();
    const confirmation = confirmFromStdin('Continue?', {
      input,
      output,
      nonTtyTimeoutMs: 50,
      readErrorMessage: 'stdin failed',
    });

    input.end();

    await expect(confirmation).rejects.toThrow('stdin failed');
  });
});
