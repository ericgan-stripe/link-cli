import { MemoryStorage } from '@stripe/link-sdk';
import { describe, expect, it } from 'vitest';
import { resolveAuthInfo } from './utils';

describe('resolveAuthInfo', () => {
  it('normalizes comma-delimited stored scopes for auth status', () => {
    const storage = new MemoryStorage({
      access_token: 'access_token_1234567890',
      refresh_token: 'refresh_token_1234567890',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read,payment_methods.agentic',
    });

    const info = resolveAuthInfo(undefined, storage);
    expect(info.authenticated).toBe(true);
    if (!info.authenticated || info.source !== 'storage') {
      throw new Error('expected storage auth info');
    }

    expect(info.scope).toBe('userinfo:read payment_methods.agentic');
  });

  it('normalizes space-delimited stored scopes for auth status', () => {
    const storage = new MemoryStorage({
      access_token: 'access_token_1234567890',
      refresh_token: 'refresh_token_1234567890',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'userinfo:read   payment_methods.agentic',
    });

    const info = resolveAuthInfo(undefined, storage);
    expect(info.authenticated).toBe(true);
    if (!info.authenticated || info.source !== 'storage') {
      throw new Error('expected storage auth info');
    }

    expect(info.scope).toBe('userinfo:read payment_methods.agentic');
  });
});
