import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  authorizationHeader,
  base64urlPad,
  parsePrivateTokenChallenges,
  parseWwwAuthenticate,
} from './private-token';

describe('PrivateToken challenge parsing', () => {
  it('splits PrivateToken and Identity-Presentation from one header', () => {
    const challenge = Buffer.from('challenge-bytes');
    const tokenKey = Buffer.from('token-key-bytes');
    const header = `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}", max-age=300, Identity-Presentation`;

    expect(parseWwwAuthenticate(header)).toEqual([
      {
        scheme: 'PrivateToken',
        params: {
          challenge: base64urlPad(challenge),
          'token-key': base64urlPad(tokenKey),
          'max-age': '300',
        },
      },
      { scheme: 'Identity-Presentation', params: {} },
    ]);
  });

  it('parses a padded quoted PrivateToken challenge on a 401', () => {
    const tokenType = Buffer.from([0x00, 0x02]);
    const rest = Buffer.from('issuer.example');
    const challenge = Buffer.concat([tokenType, rest]);
    const tokenKey = Buffer.alloc(32, 4);
    const response = {
      status: 401,
      headers: new Headers({
        'WWW-Authenticate': `PrivateToken challenge="${base64urlPad(challenge)}", token-key="${base64urlPad(tokenKey)}"`,
      }),
    };

    expect(parsePrivateTokenChallenges(response)).toEqual([
      {
        challenge: new Uint8Array(challenge),
        tokenKey: new Uint8Array(tokenKey),
        challengeDigest: new Uint8Array(
          createHash('sha256').update(challenge).digest(),
        ),
        tokenKeyId: new Uint8Array(
          createHash('sha256').update(tokenKey).digest(),
        ),
      },
    ]);
  });

  it('ignores non-401 responses', () => {
    expect(
      parsePrivateTokenChallenges({
        status: 402,
        headers: new Headers({
          'WWW-Authenticate': 'PrivateToken challenge="AAEC"',
        }),
      }),
    ).toEqual([]);
  });

  it('quotes a padded token in the Authorization header', () => {
    expect(authorizationHeader('abc')).toBe('PrivateToken token="abc="');
  });
});
