import {
  type AuthStorage,
  type AuthTokens,
  storage as defaultStorage,
} from '@stripe/link-sdk';
import { Cli } from 'incur';
import { Text } from 'ink';
import React from 'react';
import {
  buildAuthorizationDetails,
  parseAuthorizationDetails,
} from '../../auth/authorization-details';
import {
  formatLoginAccessPrompt,
  resolveLoginAccessPlan,
} from '../../auth/login-access';
import { normalizeScopeInput } from '../../auth/scopes';
import type { IAuthResource, JsonValue } from '../../auth/types';
import { pollUntil } from '../../utils/poll-until';
import { renderInteractive } from '../../utils/render-interactive';
import { sanitizeDeep } from '../../utils/sanitize-text';
import type { UpdateInfoProvider } from '../../utils/update-info';
import { confirmLoginAccess } from './confirm-login-access';
import { Login } from './login';
import { Logout } from './logout';
import { loginOptions, statusOptions } from './schema';
import { AuthStatus } from './status';
import { resolveAuthInfo } from './utils';

interface PollAuthOptions {
  interval: number;
  maxAttempts: number;
  timeout: number;
}

async function* pollAuthStatus(
  authResource: IAuthResource,
  storage: AuthStorage,
  opts: PollAuthOptions,
  update?: {
    current_version: string;
    latest_version: string;
    update_command: string;
  },
) {
  for await (const result of pollUntil({
    fn: async () => {
      const pending = storage.getPendingDeviceAuth();
      if (pending) {
        const tokens = await authResource.pollDeviceAuth(pending.device_code);
        if (tokens) {
          storage.setAuth(tokens);
          storage.clearPendingDeviceAuth();
        }
      }

      const currentPending = storage.getPendingDeviceAuth();
      if (currentPending) {
        return {
          authenticated: false as const,
          credentials_path: storage.getPath(),
          ...(update && { update }),
          pending: true,
          verification_url: currentPending.verification_url,
          phrase: currentPending.phrase,
        };
      }

      const auth = storage.getAuth();
      if (auth) {
        return {
          authenticated: true as const,
          access_token: `${auth.access_token.substring(0, 20)}...`,
          token_type: auth.token_type,
          credentials_path: storage.getPath(),
          ...(auth.scope && { scope: auth.scope }),
          ...(auth.authorization_details && {
            authorization_details: auth.authorization_details,
          }),
          ...(update && { update }),
        };
      }
      return {
        authenticated: false as const,
        credentials_path: storage.getPath(),
        ...(update && { update }),
      };
    },
    isTerminal: (status) => status.authenticated,
    interval: opts.interval,
    maxAttempts: opts.maxAttempts,
    timeout: opts.timeout,
  })) {
    yield result.value;
  }
}

async function maybeRevokeAndClearAuth(
  authResource: IAuthResource,
  storage: AuthStorage,
) {
  const auth = storage.getAuth();
  if (auth?.refresh_token) {
    try {
      await authResource.revokeToken(auth.refresh_token);
    } catch {
      // best-effort: clear local storage regardless
    }
  }
  storage.clearAuth();
  storage.clearPendingDeviceAuth();
}

export function createAuthCli(
  authResource: IAuthResource,
  getUpdateInfo?: UpdateInfoProvider,
  authStorage?: AuthStorage,
  envAccessToken?: string,
) {
  const storage = authStorage ?? defaultStorage;
  const cli = Cli.create('auth', {
    description: 'Authentication commands',
  });

  cli.command('login', {
    description: 'Authenticate with Link',
    options: loginOptions,
    outputPolicy: 'agent-only' as const,
    async *run(c) {
      const clientName = c.options.clientName?.trim();
      let scope = normalizeScopeInput(c.options.scope);
      let authorizationDetails: JsonValue[] | undefined;
      if (!clientName || clientName.length === 0) {
        return c.error({
          code: 'INVALID_INPUT',
          message: 'client-name must be a non-empty string',
        });
      }
      if (c.options.scope !== undefined && !scope) {
        return c.error({
          code: 'INVALID_INPUT',
          message: 'scope must be a non-empty string when provided',
        });
      }
      try {
        // Fold --source-action flags into the authorization details up front so
        // downstream (the access plan and the login request) treats source like
        // any other authorization-detail type.
        authorizationDetails = buildAuthorizationDetails(
          c.options.sourceActions,
          parseAuthorizationDetails(c.options.authorizationDetail),
        );
      } catch (error) {
        return c.error({
          code: 'INVALID_INPUT',
          message: (error as Error).message,
        });
      }

      const existingAuth = storage.getAuth();
      if (existingAuth?.refresh_token) {
        try {
          const refreshed = await authResource.refreshToken(
            existingAuth.refresh_token,
          );
          storage.setAuth(refreshed);
          // Figure out if this login attempt would unintentionally narrow access
          const accessPlan = resolveLoginAccessPlan({
            requestedScope: scope,
            requestedAuthorizationDetails: authorizationDetails,
            existingScope: refreshed.scope ?? existingAuth.scope,
            existingAuthorizationDetails:
              refreshed.authorization_details ??
              existingAuth.authorization_details,
          });
          const alreadyLoggedInMessage =
            'You are already logged in. To switch accounts, run `link-cli auth logout` first.';

          if (accessPlan.shouldEarlyExit) {
            const alreadyLoggedIn = sanitizeDeep({
              authenticated: true,
              message: alreadyLoggedInMessage,
            });
            if (!c.agent && !c.formatExplicit) {
              return renderInteractive(
                <Text color="yellow">{alreadyLoggedInMessage}</Text>,
                () => alreadyLoggedIn,
              );
            }
            yield alreadyLoggedIn;
            return;
          }

          if (accessPlan.shouldPrompt) {
            try {
              const shouldAddExistingAccess = await confirmLoginAccess(
                formatLoginAccessPrompt(accessPlan),
              );

              if (shouldAddExistingAccess) {
                scope = accessPlan.mergedScope;
                authorizationDetails = accessPlan.mergedAuthorizationDetails;
              }
            } catch (error) {
              return c.error({
                code: 'INVALID_INPUT',
                message: (error as Error).message,
              });
            }
          }
        } catch {
          // Session not usable — fall through to full re-auth below
        }
      }

      if (!c.agent && !c.formatExplicit) {
        return renderInteractive(
          <Login
            authResource={authResource}
            clientName={clientName}
            scope={scope}
            authorizationDetails={authorizationDetails}
            authStorage={storage}
            onComplete={() => {}}
          />,
          () => ({ authenticated: true, token_type: 'Bearer' }),
        );
      }

      const authRequest = await authResource.initiateDeviceAuth({
        clientName,
        scope,
        authorizationDetails,
      });
      storage.setPendingDeviceAuth({
        device_code: authRequest.device_code,
        interval: authRequest.interval,
        expires_at: Date.now() + authRequest.expires_in * 1000,
        verification_url: authRequest.verification_url_complete,
        phrase: authRequest.user_code,
      });

      const interval = c.options.interval;

      if (interval <= 0) {
        yield sanitizeDeep({
          verification_url: authRequest.verification_url_complete,
          phrase: authRequest.user_code,
          instruction:
            'Present the verification_url to the user and ask them to approve in the Link app. Then call `auth status --interval 5 --max-attempts 60` to poll until authenticated. Do not wait for the user to reply — start polling immediately.',
          _next: {
            command: 'auth status --interval 5 --max-attempts 60',
            poll_interval_seconds: authRequest.interval,
            until: 'authenticated is true',
          },
        });
        return;
      }

      yield sanitizeDeep({
        verification_url: authRequest.verification_url_complete,
        phrase: authRequest.user_code,
        instruction:
          'Present the verification_url to the user and ask them to approve in the Link app. Polling has started automatically — no further action needed.',
      });

      yield* pollAuthStatus(authResource, storage, {
        interval,
        maxAttempts: c.options.maxAttempts,
        timeout: c.options.timeout,
      });
    },
  });

  cli.command('logout', {
    description: 'Log out from Link',
    outputPolicy: 'agent-only' as const,
    async run(c) {
      await maybeRevokeAndClearAuth(authResource, storage);
      storage.deleteConfig();
      const result = { authenticated: false };

      if (!c.agent && !c.formatExplicit) {
        return renderInteractive(
          <Logout
            authResource={authResource}
            authStorage={storage}
            onComplete={() => {}}
          />,
          () => result,
        );
      }

      return result;
    },
  });

  cli.command('status', {
    description: 'Check authentication status',
    options: statusOptions,
    outputPolicy: 'agent-only' as const,
    async *run(c) {
      const opts = c.options;
      const interval = opts.interval;
      const maxAttempts = opts.maxAttempts;
      const updateInfo = await getUpdateInfo?.({
        polling: interval > 0,
      });
      const update = updateInfo
        ? {
            current_version: updateInfo.current,
            latest_version: updateInfo.latest,
            update_command: 'npm install -g @stripe/link-cli',
          }
        : undefined;

      if (!c.agent && !c.formatExplicit) {
        return renderInteractive(
          <AuthStatus
            authStorage={storage}
            envAccessToken={envAccessToken}
            onComplete={() => {}}
          />,
          () => {
            const info = resolveAuthInfo(envAccessToken, storage);
            if (info.authenticated) {
              return {
                authenticated: true as const,
                access_token: info.tokenPreview,
                token_type: info.tokenType,
                ...(info.source === 'storage' && {
                  credentials_path: info.credentialsPath,
                  ...(info.scope && { scope: info.scope }),
                  ...(info.authorizationDetails && {
                    authorization_details: info.authorizationDetails,
                  }),
                }),
                ...(update && { update }),
              };
            }
            return {
              authenticated: false as const,
              credentials_path: info.credentialsPath,
              ...(update && { update }),
            };
          },
        );
      }

      if (envAccessToken) {
        yield {
          authenticated: true as const,
          access_token: `${envAccessToken.substring(0, 20)}...`,
          token_type: 'Bearer',
          ...(update && { update }),
        };
        return;
      }

      yield* pollAuthStatus(
        authResource,
        storage,
        {
          interval,
          maxAttempts,
          timeout: opts.timeout,
        },
        update,
      );
    },
  });

  return cli;
}
