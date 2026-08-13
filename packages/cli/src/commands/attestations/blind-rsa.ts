import { createHash, randomBytes } from 'node:crypto';

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
  tokenInput: Uint8Array;
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

function base64urlEncode(buf: Uint8Array): string {
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
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
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
  if (first < 0x80) {
    return { value: first, bytesRead: 1 };
  }
  const numBytes = first & 0x7f;
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    value = value * 256 + data[offset + 1 + i];
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
  const H = createHash(hashAlg).update(mPrime).digest();

  const ps = Buffer.alloc(emLen - sLen - hLen - 2);
  const db = Buffer.concat([ps, Buffer.from([0x01]), salt]);

  const dbMask = mgf1(H, db.length, hashAlg);
  const maskedDB = Buffer.alloc(db.length);
  for (let i = 0; i < db.length; i++) {
    maskedDB[i] = db[i] ^ dbMask[i];
  }

  // Set the leftmost bits to zero
  const topBits = 8 * emLen - emBits;
  maskedDB[0] &= 0xff >> topBits;

  const em = Buffer.concat([maskedDB, H, Buffer.from([0xbc])]);
  return new Uint8Array(em);
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
  // Generate random r coprime to n
  while (true) {
    const rBytes = randomBytes(nLen);
    // Ensure r < n
    rBytes[0] = 0;
    const r = bytesToBigInt(new Uint8Array(rBytes));
    if (r <= 1n || r >= n) continue;
    // r must be coprime to n (gcd(r, n) === 1)
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

    // token_input = token_type(2) || nonce(32) || challenge_digest(32) || token_key_id(32)
    const tokenInput = new Uint8Array(
      2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE + TOKEN_KEY_ID_SIZE,
    );
    tokenInput[0] = (TOKEN_TYPE >> 8) & 0xff;
    tokenInput[1] = TOKEN_TYPE & 0xff;
    tokenInput.set(nonce, 2);
    tokenInput.set(challengeDigest, 2 + NONCE_SIZE);
    tokenInput.set(tokenKeyId, 2 + NONCE_SIZE + CHALLENGE_DIGEST_SIZE);

    // EMSA-PSS-ENCODE the token_input
    const encoded = emsaPssEncode(tokenInput, emBits);
    const m = bytesToBigInt(encoded);

    // Blind: blindedMsg = m * r^e mod n
    const { r, rInv } = generateBlindingFactor(publicKey.n, publicKey.nLen);
    const x = modPow(r, publicKey.e, publicKey.n);
    const blindedMsgInt = (m * x) % publicKey.n;
    const blindedMsg = bigIntToBytes(blindedMsgInt, publicKey.nLen);

    tokens.push({
      nonce,
      blindedMsg,
      blindInverse: rInv,
      tokenInput,
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
    const blindSigBytes = base64urlDecode(blindSigs[i]);
    const blindSigInt = bytesToBigInt(blindSigBytes);

    // Unblind: sig = blindSig * rInv mod n
    const sigInt = (blindSigInt * tokens[i].blindInverse) % publicKey.n;
    const authenticator = bigIntToBytes(sigInt, publicKey.nLen);

    // Assemble final token: token_type(2) || nonce(32) || challenge_digest(32) || token_key_id(32) || authenticator(Nk)
    const raw = new Uint8Array(
      2 +
        NONCE_SIZE +
        CHALLENGE_DIGEST_SIZE +
        TOKEN_KEY_ID_SIZE +
        publicKey.nLen,
    );
    raw[0] = (TOKEN_TYPE >> 8) & 0xff;
    raw[1] = TOKEN_TYPE & 0xff;
    raw.set(tokens[i].nonce, 2);
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

export function computeChallengeDigest(
  tokenType: number,
  issuerName: string,
  originInfo?: string,
): Uint8Array {
  // TokenChallenge struct per RFC 9577 §2.1:
  // token_type(2) || issuer_name length(2) || issuer_name || redemption_context length(1) || redemption_context || origin_info length(2) || origin_info
  const issuerBytes = Buffer.from(issuerName, 'utf-8');
  const originBytes = originInfo
    ? Buffer.from(originInfo, 'utf-8')
    : Buffer.alloc(0);

  const challenge = Buffer.alloc(
    2 + 2 + issuerBytes.length + 1 + 2 + originBytes.length,
  );
  let offset = 0;

  // token_type (uint16)
  challenge.writeUInt16BE(tokenType, offset);
  offset += 2;

  // issuer_name length (uint16) + issuer_name
  challenge.writeUInt16BE(issuerBytes.length, offset);
  offset += 2;
  issuerBytes.copy(challenge, offset);
  offset += issuerBytes.length;

  // redemption_context length (uint8) = 0 (empty)
  challenge.writeUInt8(0, offset);
  offset += 1;

  // origin_info length (uint16) + origin_info
  challenge.writeUInt16BE(originBytes.length, offset);
  offset += 2;
  if (originBytes.length > 0) {
    originBytes.copy(challenge, offset);
  }

  return new Uint8Array(createHash('sha256').update(challenge).digest());
}

export { base64urlEncode, base64urlDecode };
