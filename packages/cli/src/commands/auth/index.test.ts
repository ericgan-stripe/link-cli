import { MemoryStorage } from '@stripe/link-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthCli } from './index';

interface CliRunResult {
  exitCode: number | undefined;
  output: string;
}

async function runCli(
  argv: string[],
  storage: MemoryStorage,
  authResource: Parameters<typeof createAuthCli>[0],
): Promise<CliRunResult> {
  const cli = createAuthCli(authResource, undefined, storage);
  let output = '';
  let exitCode: number | undefined;

  await cli.serve(argv, {
    stdout(chunk) {
      output += chunk;
    },
    exit(code) {
      exitCode = code;
    },
  });

  return { exitCode, output };
}

describe('createAuthCli auth login', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps the current auth when replacement device auth initiation fails', async () => {
    const storage = new MemoryStorage({
      access_token: 'at_old',
      refresh_token: 'rt_old',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read payment_methods.agentic',
    });
    const refreshedAuth = {
      access_token: 'at_refreshed',
      refresh_token: 'rt_refreshed',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read payment_methods.agentic',
    };
    const authResource = {
      initiateDeviceAuth: vi.fn().mockRejectedValue(new Error('boom')),
      pollDeviceAuth: vi.fn(),
      refreshToken: vi.fn().mockResolvedValue(refreshedAuth),
      revokeToken: vi.fn(),
    };

    const result = await runCli(
      [
        'login',
        '--client-name',
        'My Agent',
        '--source-actions',
        'read_link_transactions',
        '--json',
      ],
      storage,
      authResource,
    );

    expect(result.exitCode).toBe(1);
    expect(result.output).toContain('boom');
    expect(authResource.revokeToken).not.toHaveBeenCalled();
    expect(storage.getPendingDeviceAuth()).toBeNull();
    expect(storage.getAuth()).toEqual(
      expect.objectContaining({
        access_token: 'at_refreshed',
        refresh_token: 'rt_refreshed',
      }),
    );
  });

  it('polls pending replacement auth even while an existing session is still stored', async () => {
    const storage = new MemoryStorage({
      access_token: 'at_old',
      refresh_token: 'rt_old',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read payment_methods.agentic',
    });
    const refreshedAuth = {
      access_token: 'at_refreshed',
      refresh_token: 'rt_refreshed',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read payment_methods.agentic',
    };
    const replacementAuth = {
      access_token: 'at_new',
      refresh_token: 'rt_new',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read payment_methods.agentic',
    };
    const authResource = {
      initiateDeviceAuth: vi.fn().mockResolvedValue({
        device_code: 'dev_123',
        user_code: 'apple-grape',
        verification_url: 'https://example.test/device',
        verification_url_complete:
          'https://example.test/device?code=apple-grape',
        expires_in: 300,
        interval: 1,
      }),
      pollDeviceAuth: vi.fn().mockResolvedValue(replacementAuth),
      refreshToken: vi.fn().mockResolvedValue(refreshedAuth),
      revokeToken: vi.fn().mockResolvedValue(undefined),
    };

    const result = await runCli(
      [
        'login',
        '--client-name',
        'My Agent',
        '--source-actions',
        'read_link_transactions',
        '--interval',
        '1',
        '--timeout',
        '5',
        '--json',
      ],
      storage,
      authResource,
    );

    expect(result.exitCode).toBeUndefined();
    expect(result.output).toContain('verification_url');
    expect(result.output).toContain('"authenticated": true');
    expect(authResource.pollDeviceAuth).toHaveBeenCalledWith('dev_123');
    expect(authResource.revokeToken).not.toHaveBeenCalled();
    expect(storage.getPendingDeviceAuth()).toBeNull();
    expect(storage.getAuth()).toEqual(
      expect.objectContaining({
        access_token: 'at_new',
        refresh_token: 'rt_new',
      }),
    );
  });
});
