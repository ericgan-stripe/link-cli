import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const TOKEN_TYPE = 0x0002;
const NONCE_SIZE = 32;
const CHALLENGE_DIGEST_SIZE = 32;
const TOKEN_KEY_ID_SIZE = 32;

interface RsaPublicKey {
  n: bigint;
  e: bigint;
  nLen: number;
}

interface BlindedToken {
  nonce: Uint8Array;
  blindedMsg: Uint8Array;
  blindInverse: bigint;
  encodedMessage: Uint8Array;
}

export interface BlindingState {
  tokens: BlindedToken[];
  publicKey: RsaPublicKey;
  challengeDigest: Uint8Array;
  tokenKeyId: Uint8Array;
}

export interface FinalToken {
  raw: Uint8Array;
  base64url: string;
}

export function base64urlEncode(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

function base64urlDecode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return ((oldS % m) + m) % m;
}

function parseSpkiPublicKey(spkiDer: Uint8Array): RsaPublicKey {
  // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
  //
  // The DER must be walked structurally, not scanned for tag bytes: an
  // id-RSASSA-PSS AlgorithmIdentifier carries nested hash/MGF1/saltLength
  // parameters whose bytes include values that look like BIT STRING and
  // INTEGER tags.
  const spki = readSequence(spkiDer, 0);

  // Skip the AlgorithmIdentifier, then read the BIT STRING that follows it.
  const algorithm = readTlv(spkiDer, spki.contentStart);
  const bitString = readTlv(spkiDer, algorithm.end);
  if (bitString.tag !== 0x03) {
    throw new Error(
      `Expected BIT STRING in SPKI, got 0x${bitString.tag.toString(16)}`,
    );
  }

  // First content byte of a BIT STRING is the unused-bits count (0 here).
  const rsaPublicKeyDer = spkiDer.slice(
    bitString.contentStart + 1,
    bitString.end,
  );

  const rsaPublicKey = readSequence(rsaPublicKeyDer, 0);
  const modulus = readInteger(rsaPublicKeyDer, rsaPublicKey.contentStart);
  const exponent = readInteger(rsaPublicKeyDer, modulus.end);

  return {
    n: bytesToBigInt(modulus.value),
    e: bytesToBigInt(exponent.value),
    nLen: modulus.value.length,
  };
}

interface Tlv {
  tag: number;
  contentStart: number;
  end: number;
}

function readTlv(data: Uint8Array, offset: number): Tlv {
  if (offset >= data.length) {
    throw new Error(`Unexpected end of DER at offset ${offset}`);
  }
  const tag = data[offset];
  if (tag === undefined) {
    throw new Error(`Unexpected end of DER at offset ${offset}`);
  }
  const { value: length, bytesRead } = parseDerLength(data, offset + 1);
  const contentStart = offset + 1 + bytesRead;
  const end = contentStart + length;
  if (end > data.length) {
    throw new Error(`DER element at offset ${offset} overruns the buffer`);
  }
  return { tag, contentStart, end };
}

function readSequence(data: Uint8Array, offset: number): Tlv {
  const tlv = readTlv(data, offset);
  if (tlv.tag !== 0x30) {
    throw new Error(
      `Expected SEQUENCE at offset ${offset}, got 0x${tlv.tag.toString(16)}`,
    );
  }
  return tlv;
}

function readInteger(
  data: Uint8Array,
  offset: number,
): { value: Uint8Array; end: number } {
  const tlv = readTlv(data, offset);
  if (tlv.tag !== 0x02) {
    throw new Error(
      `Expected INTEGER at offset ${offset}, got 0x${tlv.tag.toString(16)}`,
    );
  }
  let value = data.slice(tlv.contentStart, tlv.end);
  // Strip the DER sign byte.
  if (value.length > 1 && value[0] === 0x00) {
    value = value.slice(1);
  }
  return { value, end: tlv.end };
}

function parseDerLength(
  data: Uint8Array,
  offset: number,
): { value: number; bytesRead: number } {
  const first = data[offset];
  if (first === undefined) {
    throw new Error(`Unexpected end of DER at offset ${offset}`);
  }
  if (first < 0x80) {
    return { value: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0 || offset + numBytes >= data.length) {
    throw new Error(`Invalid DER length at offset ${offset}`);
  }
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    const byte = data[offset + 1 + i];
    if (byte === undefined) {
      throw new Error(`Unexpected end of DER at offset ${offset + 1 + i}`);
    }
    value = value * 256 + byte;
  }
  return { value, bytesRead: 1 + numBytes };
}

// EMSA-PSS encoding for RSA-PSS (RFC 8017 §9.1.1) with SHA-384
function emsaPssEncode(message: Uint8Array, emBits: number): Uint8Array {
  const hashAlg = 'sha384';
  const hLen = 48; // SHA-384 output
  const sLen = 48; // salt length = hash length for RSABSSA-SHA384-PSS
  const emLen = Math.ceil(emBits / 8);

  const mHash = createHash(hashAlg).update(message).digest();
  if (emLen < hLen + sLen + 2) {
    throw new Error('Encoding error: emLen too small');
  }

  const salt = randomBytes(sLen);
  // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const mPrime = Buffer.concat([Buffer.alloc(8), mHash, salt]);
  const h = createHash(hashAlg).update(mPrime).digest();

  const ps = Buffer.alloc(emLen - sLen - hLen - 2);
  const db = Buffer.concat([ps, Buffer.from([0x01]), salt]);

  const dbMask = mgf1(h, db.length, hashAlg);
  const maskedDb = Buffer.alloc(db.length);
  for (let i = 0; i < db.length; i++) {
    maskedDb.writeUInt8(db.readUInt8(i) ^ dbMask.readUInt8(i), i);
  }

  // Set the leftmost bits to zero.
  const topBits = 8 * emLen - emBits;
  maskedDb.writeUInt8(maskedDb.readUInt8(0) & (0xff >> topBits), 0);

  return new Uint8Array(Buffer.concat([maskedDb, h, Buffer.from([0xbc])]));
}

function mgf1(seed: Buffer, length: number, hashAlg: string): Buffer {
  const hLen = hashAlg === 'sha384' ? 48 : 32;
  const result = Buffer.alloc(length);
  let offset = 0;
  let counter = 0;

  while (offset < length) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    const hash = createHash(hashAlg).update(seed).update(c).digest();
    const toCopy = Math.min(hLen, length - offset);
    hash.copy(result, offset, 0, toCopy);
    offset += toCopy;
    counter++;
  }

  return result;
}

function generateBlindingFactor(
  n: bigint,
  nLen: number,
): { r: bigint; rInv: bigint } {
  while (true) {
    const rBytes = randomBytes(nLen);
    rBytes[0] = 0;
    const r = bytesToBigInt(new Uint8Array(rBytes));
    if (r <= 1n || r >= n) continue;
    const rInv = modInverse(r, n);
    if ((r * rInv) % n === 1n) {
      return { r, rInv };
    }
  }
}

export function generateBlindedMessages(
  spkiDer: Uint8Array,
  count: number,
  challengeDigest: Uint8Array,
): BlindingState {
  const publicKey = parseSpkiPublicKey(spkiDer);
  const tokenKeyId = new Uint8Array(
    createHash('sha256').update(spkiDer).digest(),
  );

  const emBits = publicKey.nLen * 8 - 1;
  const tokens: BlindedToken[] = [];

  for (let i = 0; i < count; i++) {
    const nonce = new Uint8Array(randomBytes(NONCE_SIZE));
    const tokenInput = new Uint8Array(
      2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE + TOKEN_KEY_ID_SIZE,
    );
    tokenInput[0] = (TOKEN_TYPE >> 8) & 0xff;
    tokenInput[1] = TOKEN_TYPE & 0xff;
    tokenInput.set(nonce, 2);
    tokenInput.set(challengeDigest, 2 + NONCE_SIZE);
    tokenInput.set(tokenKeyId, 2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE);

    const encoded = emsaPssEncode(tokenInput, emBits);
    const message = bytesToBigInt(encoded);
    const { r, rInv } = generateBlindingFactor(publicKey.n, publicKey.nLen);
    const blindedMessage =
      (message * modPow(r, publicKey.e, publicKey.n)) % publicKey.n;

    tokens.push({
      nonce,
      blindedMsg: bigIntToBytes(blindedMessage, publicKey.nLen),
      blindInverse: rInv,
      encodedMessage: encoded,
    });
  }

  return { tokens, publicKey, challengeDigest, tokenKeyId };
}

export function unblindSignatures(
  state: BlindingState,
  blindSigs: string[],
): FinalToken[] {
  const { tokens, publicKey, tokenKeyId } = state;

  if (blindSigs.length !== tokens.length) {
    throw new Error(
      `Expected ${tokens.length} blind signatures, got ${blindSigs.length}`,
    );
  }

  const results: FinalToken[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const blindSignature = blindSigs[i];
    if (!token || blindSignature === undefined) {
      throw new Error(`Missing blind signature state at index ${i}`);
    }
    const blindSigBytes = base64urlDecode(blindSignature);
    const blindSigInt = bytesToBigInt(blindSigBytes);
    const sigInt = (blindSigInt * token.blindInverse) % publicKey.n;
    const authenticator = bigIntToBytes(sigInt, publicKey.nLen);
    const recoveredMessage = bigIntToBytes(
      modPow(sigInt, publicKey.e, publicKey.n),
      publicKey.nLen,
    );
    if (
      !timingSafeEqual(
        Buffer.from(recoveredMessage),
        Buffer.from(token.encodedMessage),
      )
    ) {
      throw new Error(`Blind signature ${i} failed verification`);
    }

    const raw = new Uint8Array(
      2 +
        NONCE_SIZE +
        CHALLENGE_DIGEST_SIZE +
        TOKEN_KEY_ID_SIZE +
        publicKey.nLen,
    );
    raw[0] = (TOKEN_TYPE >> 8) & 0xff;
    raw[1] = TOKEN_TYPE & 0xff;
    raw.set(token.nonce, 2);
    raw.set(state.challengeDigest, 2 + NONCE_SIZE);
    raw.set(tokenKeyId, 2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE);
    raw.set(
      authenticator,
      2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE + TOKEN_KEY_ID_SIZE,
    );

    results.push({
      raw,
      base64url: base64urlEncode(raw),
    });
  }

  return results;
}

/**
 * Stable TokenChallenge this profile pools against: fixed issuer_name, empty
 * redemption_context, empty origin_info (RFC 9577).
 */
export function encodeStableTokenChallenge(
  tokenType: number,
  issuerName: string,
): Uint8Array {
  const issuerBytes = Buffer.from(issuerName, 'utf-8');
  const challenge = Buffer.alloc(2 + 2 + issuerBytes.length + 1 + 2);
  let offset = 0;

  challenge.writeUInt16BE(tokenType, offset);
  offset += 2;
  challenge.writeUInt16BE(issuerBytes.length, offset);
  offset += 2;
  issuerBytes.copy(challenge, offset);
  offset += issuerBytes.length;
  challenge.writeUInt8(0, offset);
  offset += 1;
  challenge.writeUInt16BE(0, offset);

  return new Uint8Array(challenge);
}

export function computeChallengeDigest(
  tokenType: number,
  issuerName: string,
): Uint8Array {
  return new Uint8Array(
    createHash('sha256')
      .update(encodeStableTokenChallenge(tokenType, issuerName))
      .digest(),
  );
}

export interface ParsedFinalToken {
  tokenType: number;
  nonce: Uint8Array;
  challengeDigest: Uint8Array;
  tokenKeyId: Uint8Array;
  authenticator: Uint8Array;
  raw: Uint8Array;
}

export function parseFinalToken(token: string): ParsedFinalToken {
  const raw = base64urlDecode(token);
  const prefix = 2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE + TOKEN_KEY_ID_SIZE;
  if (raw.length <= prefix) {
    throw new Error('PrivateToken is too short');
  }
  const tokenType = ((raw[0] ?? 0) << 8) | (raw[1] ?? 0);
  if (tokenType !== TOKEN_TYPE) {
    throw new Error(
      `Unsupported PrivateToken type 0x${tokenType.toString(16)}`,
    );
  }
  return {
    tokenType,
    nonce: raw.slice(2, 2 + NONCE_SIZE),
    challengeDigest: raw.slice(
      2 + NONCE_SIZE,
      2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE,
    ),
    tokenKeyId: raw.slice(2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE, prefix),
    authenticator: raw.slice(prefix),
    raw,
  };
}
