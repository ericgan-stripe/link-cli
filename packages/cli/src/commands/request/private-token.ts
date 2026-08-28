import { createHash } from 'node:crypto';

const TOKEN_TYPE_BLIND_RSA = 0x0002;

export interface PrivateTokenChallenge {
  challenge: Uint8Array;
  tokenKey?: Uint8Array;
  maxAge?: number;
  challengeDigest: Uint8Array;
  tokenKeyId?: Uint8Array;
}

interface WwwAuthenticateChallenge {
  scheme: string;
  params: Record<string, string>;
}

function skipWhitespace(input: string, start: number): number {
  let index = start;
  while (index < input.length && /\s/.test(input[index] ?? '')) {
    index += 1;
  }
  return index;
}

function isSchemeChar(char: string): boolean {
  return /[A-Za-z0-9._+-]/.test(char);
}

/**
 * Splits WWW-Authenticate into challenges. A comma starts a new scheme when
 * the following token is not an auth-param (`name=value`).
 */
export function parseWwwAuthenticate(
  header: string,
): WwwAuthenticateChallenge[] {
  const challenges: WwwAuthenticateChallenge[] = [];
  let index = 0;
  const length = header.length;

  while (index < length) {
    index = skipWhitespace(header, index);
    while (header[index] === ',') {
      index = skipWhitespace(header, index + 1);
    }
    if (index >= length) {
      break;
    }

    const schemeStart = index;
    while (index < length && isSchemeChar(header[index] ?? '')) {
      index += 1;
    }
    const scheme = header.slice(schemeStart, index);
    if (scheme.length === 0) {
      break;
    }
    index = skipWhitespace(header, index);

    const paramStart = index;
    while (index < length) {
      const char = header[index];
      if (char === '"') {
        index += 1;
        while (index < length && header[index] !== '"') {
          if (header[index] === '\\') {
            index += 1;
          }
          index += 1;
        }
        if (index < length) {
          index += 1;
        }
        continue;
      }
      if (char === ',') {
        let lookahead = skipWhitespace(header, index + 1);
        const nameStart = lookahead;
        while (lookahead < length && isSchemeChar(header[lookahead] ?? '')) {
          lookahead += 1;
        }
        lookahead = skipWhitespace(header, lookahead);
        if (lookahead < length && header[lookahead] === '=') {
          index += 1;
          continue;
        }
        break;
      }
      index += 1;
    }

    challenges.push({
      scheme,
      params: parseAuthParams(header.slice(paramStart, index).trim()),
    });
  }

  return challenges;
}

function parseAuthParams(input: string): Record<string, string> {
  const params: Record<string, string> = {};
  const pattern = /([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  for (const match of input.matchAll(pattern)) {
    const name = match[1]?.toLowerCase();
    if (!name) {
      continue;
    }
    const quoted = match[2];
    const token = match[3];
    params[name] =
      quoted !== undefined ? quoted.replace(/\\(.)/g, '$1') : (token ?? '');
  }
  return params;
}

function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function base64urlPad(value: Uint8Array | string): string {
  const unpadded =
    typeof value === 'string'
      ? value.replace(/=+$/, '')
      : Buffer.from(value).toString('base64url');
  const pad = (4 - (unpadded.length % 4)) % 4;
  return `${unpadded}${'='.repeat(pad)}`;
}

export function parsePrivateTokenChallenges(
  response: Pick<Response, 'status' | 'headers'>,
): PrivateTokenChallenge[] {
  if (response.status !== 401) {
    return [];
  }
  const header = response.headers.get('www-authenticate') ?? '';
  const challenges: PrivateTokenChallenge[] = [];
  for (const entry of parseWwwAuthenticate(header)) {
    if (entry.scheme.toLowerCase() !== 'privatetoken') {
      continue;
    }
    if (!entry.params.challenge) {
      throw new Error(
        'Invalid PrivateToken challenge: challenge parameter is missing',
      );
    }
    const challenge = decodeBase64Url(entry.params.challenge);
    if (challenge.length < 2) {
      throw new Error('Invalid PrivateToken challenge: challenge is too short');
    }
    const tokenType = ((challenge[0] ?? 0) << 8) | (challenge[1] ?? 0);
    if (tokenType !== TOKEN_TYPE_BLIND_RSA) {
      throw new Error(
        `Unsupported PrivateToken type 0x${tokenType.toString(16)}`,
      );
    }
    const tokenKey = entry.params['token-key']
      ? decodeBase64Url(entry.params['token-key'])
      : undefined;
    const maxAge = entry.params['max-age']
      ? Number(entry.params['max-age'])
      : undefined;
    challenges.push({
      challenge,
      ...(tokenKey ? { tokenKey } : {}),
      ...(maxAge !== undefined && Number.isFinite(maxAge) ? { maxAge } : {}),
      challengeDigest: new Uint8Array(
        createHash('sha256').update(challenge).digest(),
      ),
      ...(tokenKey
        ? {
            tokenKeyId: new Uint8Array(
              createHash('sha256').update(tokenKey).digest(),
            ),
          }
        : {}),
    });
  }
  return challenges;
}

export function authorizationHeader(token: string): string {
  return `PrivateToken token="${base64urlPad(token)}"`;
}
