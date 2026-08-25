import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  generateBlindedMessages,
  unblindSignatures,
} from '@/resources/attestations-crypto';
import { describe, expect, it } from 'vitest';

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  return new Uint8Array(
    Buffer.from(value.toString(16).padStart(length * 2, '0'), 'hex'),
  );
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let current = base % modulus;
  let remaining = exponent;
  while (remaining > 0n) {
    if (remaining & 1n) {
      result = (result * current) % modulus;
    }
    remaining >>= 1n;
    current = (current * current) % modulus;
  }
  return result;
}

function decodeJwkInteger(value: string): bigint {
  return bytesToBigInt(new Uint8Array(Buffer.from(value, 'base64url')));
}

describe('Blind RSA finalization', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicExponent: 0x10001,
  });
  const spki = new Uint8Array(
    publicKey.export({ format: 'der', type: 'spki' }),
  );
  const privateJwk = privateKey.export({ format: 'jwk' });
  const modulus = decodeJwkInteger(privateJwk.n as string);
  const privateExponent = decodeJwkInteger(privateJwk.d as string);

  it('accepts a correctly signed blinded message', () => {
    const state = generateBlindedMessages(
      spki,
      1,
      new Uint8Array(randomBytes(32)),
    );
    const token = state.tokens[0];
    expect(token).toBeDefined();
    if (!token) {
      throw new Error('Expected one blinded token');
    }
    const blindedMessage = bytesToBigInt(token.blindedMsg);
    const blindSignature = bigIntToBytes(
      modPow(blindedMessage, privateExponent, modulus),
      token.blindedMsg.length,
    );

    const tokens = unblindSignatures(state, [
      Buffer.from(blindSignature).toString('base64url'),
    ]);

    expect(tokens).toHaveLength(1);
    expect(tokens[0]?.raw).toHaveLength(2 + 32 + 32 + 32 + 128);
  });

  it('rejects an invalid blind signature after unblinding', () => {
    const state = generateBlindedMessages(
      spki,
      1,
      new Uint8Array(randomBytes(32)),
    );
    const token = state.tokens[0];
    expect(token).toBeDefined();
    if (!token) {
      throw new Error('Expected one blinded token');
    }
    const invalidSignature = Buffer.alloc(token.blindedMsg.length).toString(
      'base64url',
    );

    expect(() => unblindSignatures(state, [invalidSignature])).toThrow(
      'Blind signature 0 failed verification',
    );
  });
});
