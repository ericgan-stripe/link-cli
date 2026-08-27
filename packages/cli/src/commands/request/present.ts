import { createHash, createSign, sign as signEd25519 } from 'node:crypto';
import { sanitizeDeep } from '../../utils/sanitize-text';
import { loadOrCreateHolderKey } from '../credentials/holder-key';
import type { HolderKeyType } from '../credentials/holder-key';

export type ClaimPathComponent = string | number | null;
export type ClaimReference = string | ClaimPathComponent[];

/** The claims-required challenge a verifier returns for identity disclosure. */
export interface ClaimsChallenge {
  aud: string;
  nonce: string;
  claims: ClaimReference[];
  purpose?: string;
  formats: string[];
  trusted_issuers?: string[];
}

const CLAIMS_REQUIRED_TYPE = 'urn:aap:claims-required';
const SUPPORTED_FORMAT = 'dc+sd-jwt';

function base64url(input: Buffer | Uint8Array | string): string {
  return Buffer.from(input as Buffer).toString('base64url');
}

function jsonSegment(value: unknown): string {
  return base64url(JSON.stringify(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseClaimReference(value: unknown): ClaimReference | null {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    typeof value[0] !== 'string' ||
    value[0].length === 0
  ) {
    return null;
  }
  for (const component of value) {
    if (
      component !== null &&
      typeof component !== 'string' &&
      !(
        typeof component === 'number' &&
        Number.isInteger(component) &&
        component >= 0
      )
    ) {
      return null;
    }
  }
  return value as ClaimPathComponent[];
}

/**
 * Recognizes a claims-required challenge only when all protocol signals agree.
 * Unrelated 401 responses pass through; malformed identity challenges fail closed.
 */
export function parseClaimsChallenge(
  response: Pick<Response, 'status' | 'headers'>,
  body: string,
): ClaimsChallenge | null {
  if (response.status !== 401) {
    return null;
  }
  const authenticate = response.headers.get('www-authenticate') ?? '';
  if (!/(?:^|,)\s*Identity-Presentation(?:\s|,|$)/i.test(authenticate)) {
    return null;
  }
  const contentType = (response.headers.get('content-type') ?? '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== 'application/problem+json') {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = sanitizeDeep(JSON.parse(body));
  } catch {
    throw new Error('Invalid claims challenge: body is not JSON');
  }
  if (!isRecord(parsed) || parsed.type !== CLAIMS_REQUIRED_TYPE) {
    return null;
  }
  if (
    typeof parsed.aud !== 'string' ||
    parsed.aud.length === 0 ||
    typeof parsed.nonce !== 'string' ||
    parsed.nonce.length === 0 ||
    !Array.isArray(parsed.claims) ||
    !Array.isArray(parsed.formats)
  ) {
    throw new Error('Invalid claims challenge: required fields are missing');
  }

  const claims = parsed.claims.map(parseClaimReference);
  if (claims.some((claim) => claim === null)) {
    throw new Error('Invalid claims challenge: malformed claim reference');
  }
  if (!parsed.formats.every((format) => typeof format === 'string')) {
    throw new Error('Invalid claims challenge: malformed formats');
  }
  if (
    parsed.trusted_issuers !== undefined &&
    (!Array.isArray(parsed.trusted_issuers) ||
      !parsed.trusted_issuers.every(
        (issuer) => typeof issuer === 'string' && issuer.length > 0,
      ))
  ) {
    throw new Error('Invalid claims challenge: malformed trusted_issuers');
  }

  return {
    aud: parsed.aud,
    nonce: parsed.nonce,
    claims: claims as ClaimReference[],
    formats: parsed.formats as string[],
    ...(typeof parsed.purpose === 'string' ? { purpose: parsed.purpose } : {}),
    ...(parsed.trusted_issuers !== undefined
      ? { trusted_issuers: parsed.trusted_issuers as string[] }
      : {}),
  };
}

export function supportsPreProvisionedPresentation(
  challenge: ClaimsChallenge,
): boolean {
  return challenge.formats.includes(SUPPORTED_FORMAT);
}

export interface Presentation {
  presentation: string;
  disclosed: ClaimReference[];
  withheld: string[];
  /** Claims asked for that the credential cannot selectively disclose. */
  unavailable: ClaimReference[];
}

interface DecodedDisclosure {
  encoded: string;
  digest: string;
  name?: string;
  value: unknown;
}

function decodeJsonSegment(segment: string, label: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch (error) {
    throw new Error(`Invalid ${label}`, { cause: error });
  }
}

function resolveSdHashAlgorithm(payload: Record<string, unknown>): {
  nodeName: 'sha256' | 'sha384' | 'sha512';
  sdName: 'sha-256' | 'sha-384' | 'sha-512';
} {
  const sdName = payload._sd_alg ?? 'sha-256';
  if (sdName === 'sha-256') {
    return { nodeName: 'sha256', sdName };
  }
  if (sdName === 'sha-384') {
    return { nodeName: 'sha384', sdName };
  }
  if (sdName === 'sha-512') {
    return { nodeName: 'sha512', sdName };
  }
  throw new Error(`Unsupported SD-JWT hash algorithm: ${String(sdName)}`);
}

function decodeDisclosures(
  encodedDisclosures: string[],
  hashName: string,
): Map<string, DecodedDisclosure> {
  const disclosures = new Map<string, DecodedDisclosure>();
  for (const encoded of encodedDisclosures) {
    const value = decodeJsonSegment(encoded, 'SD-JWT disclosure');
    if (
      !Array.isArray(value) ||
      (value.length !== 2 && value.length !== 3) ||
      (value.length === 3 && typeof value[1] !== 'string')
    ) {
      throw new Error('Invalid SD-JWT disclosure');
    }
    const digest = base64url(createHash(hashName).update(encoded).digest());
    disclosures.set(digest, {
      encoded,
      digest,
      ...(value.length === 3 ? { name: value[1] as string } : {}),
      value: value.length === 3 ? value[2] : value[1],
    });
  }
  return disclosures;
}

function revealArrayElement(
  element: unknown,
  remainingPath: ClaimPathComponent[],
  disclosures: Map<string, DecodedDisclosure>,
  selected: Set<string>,
): boolean {
  if (isRecord(element) && typeof element['...'] === 'string') {
    const disclosure = disclosures.get(element['...']);
    if (!disclosure || disclosure.name !== undefined) {
      return false;
    }
    selected.add(disclosure.digest);
    return revealPath(disclosure.value, remainingPath, disclosures, selected);
  }
  return revealPath(element, remainingPath, disclosures, selected);
}

function revealPath(
  node: unknown,
  path: ClaimPathComponent[],
  disclosures: Map<string, DecodedDisclosure>,
  selected: Set<string>,
): boolean {
  if (path.length === 0) {
    return true;
  }
  const [component, ...remaining] = path;

  if (Array.isArray(node)) {
    if (component === null) {
      let matched = false;
      for (const element of node) {
        matched =
          revealArrayElement(element, remaining, disclosures, selected) ||
          matched;
      }
      return matched;
    }
    if (typeof component !== 'number' || component >= node.length) {
      return false;
    }
    return revealArrayElement(
      node[component],
      remaining,
      disclosures,
      selected,
    );
  }

  if (!isRecord(node) || typeof component !== 'string') {
    return false;
  }
  if (Object.hasOwn(node, component)) {
    return revealPath(node[component], remaining, disclosures, selected);
  }
  const digests = Array.isArray(node._sd) ? node._sd : [];
  for (const digest of digests) {
    if (typeof digest !== 'string') {
      continue;
    }
    const disclosure = disclosures.get(digest);
    if (disclosure?.name === component) {
      selected.add(disclosure.digest);
      return revealPath(disclosure.value, remaining, disclosures, selected);
    }
  }
  return false;
}

function claimPath(reference: ClaimReference): ClaimPathComponent[] {
  return typeof reference === 'string' ? [reference] : reference;
}

export function claimReferenceKey(reference: ClaimReference): string {
  return JSON.stringify(claimPath(reference));
}

/**
 * Builds an SD-JWT-VC presentation with only the disclosures needed to resolve
 * the requested claim references, including nested claims path pointers.
 */
export function buildPresentation(options: {
  credential: string;
  keyFile: string;
  keyType: HolderKeyType;
  aud: string;
  nonce: string;
  disclose: ClaimReference[];
}): Presentation {
  const { credential, keyFile, keyType, aud, nonce, disclose } = options;
  const [issuerJwt, ...rest] = credential.split('~');
  const jwtParts = issuerJwt.split('.');
  if (jwtParts.length !== 3) {
    throw new Error('Invalid SD-JWT issuer credential');
  }
  const payload = decodeJsonSegment(jwtParts[1], 'SD-JWT payload');
  if (!isRecord(payload)) {
    throw new Error('Invalid SD-JWT payload');
  }
  const hashAlgorithm = resolveSdHashAlgorithm(payload);
  const available = rest.filter(Boolean);
  const disclosures = decodeDisclosures(available, hashAlgorithm.nodeName);
  const selected = new Set<string>();
  const disclosed: ClaimReference[] = [];
  const unavailable: ClaimReference[] = [];

  for (const reference of disclose) {
    const candidate = new Set(selected);
    if (revealPath(payload, claimPath(reference), disclosures, candidate)) {
      selected.clear();
      for (const digest of candidate) {
        selected.add(digest);
      }
      disclosed.push(reference);
    } else {
      unavailable.push(reference);
    }
  }

  const kept = available.filter((encoded) => {
    for (const disclosure of disclosures.values()) {
      if (disclosure.encoded === encoded) {
        return selected.has(disclosure.digest);
      }
    }
    return false;
  });
  const withheld = Array.from(disclosures.values())
    .filter((disclosure) => !selected.has(disclosure.digest))
    .map((disclosure) => disclosure.name ?? '[array element]');

  // Everything up to and including the final `~` is what sd_hash covers.
  const sdPart = `${[issuerJwt, ...kept].join('~')}~`;
  const holderKey = loadOrCreateHolderKey(keyFile, keyType);
  const alg = holderKey.type === 'ed25519' ? 'EdDSA' : 'ES256';
  const header = jsonSegment({ typ: 'kb+jwt', alg });
  const kbPayload = jsonSegment({
    aud,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    sd_hash: base64url(
      createHash(hashAlgorithm.nodeName).update(sdPart).digest(),
    ),
  });
  const signingInput = Buffer.from(`${header}.${kbPayload}`);
  const signature =
    alg === 'EdDSA'
      ? signEd25519(null, signingInput, holderKey.privateKey)
      : createSign('sha256')
          .update(signingInput)
          .sign({ key: holderKey.privateKey, dsaEncoding: 'ieee-p1363' });

  return {
    presentation: `${sdPart}${header}.${kbPayload}.${base64url(signature)}`,
    disclosed,
    withheld,
    unavailable,
  };
}

export function parseClaimList(
  claims: string | undefined,
): ClaimReference[] | null {
  if (claims === undefined) {
    return null;
  }
  const parsed = claims
    .split(',')
    .map((claim) => claim.trim())
    .filter(Boolean);
  return parsed.length > 0 ? parsed : null;
}

export function buildRequestHeaders(
  data: string | undefined,
  headers: string[],
): Record<string, string> {
  const result: Record<string, string> = {};
  if (data !== undefined) {
    result['Content-Type'] = 'application/json';
  }
  for (const header of headers) {
    const index = header.indexOf(':');
    if (index === -1) {
      throw new Error(`Invalid header "${header}". Use "Name: Value" format.`);
    }
    result[header.slice(0, index).trim()] = header.slice(index + 1).trim();
  }
  return result;
}

export function setRequestHeader(
  headers: Record<string, string>,
  name: string,
  value: string,
): void {
  for (const existing of Object.keys(headers)) {
    if (existing.toLowerCase() === name.toLowerCase()) {
      delete headers[existing];
    }
  }
  headers[name] = value;
}

export function contentDigest(body: string): string {
  return `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
}

export function formatClaimReference(reference: ClaimReference): string {
  return typeof reference === 'string' ? reference : JSON.stringify(reference);
}
