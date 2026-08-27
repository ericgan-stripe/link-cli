import { isIP } from 'node:net';
import { LinkConfigurationError } from '@/errors';

export function parseIssuerOrigin(issuer: string): URL {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch (error) {
    throw new LinkConfigurationError(`Invalid issuer URL: ${issuer}`, {
      cause: error,
    });
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    isIP(hostname) !== 0
  ) {
    throw new LinkConfigurationError(
      'Issuer must be an HTTPS origin with a DNS hostname',
    );
  }
  return url;
}

export function requireIssuerEndpoint(
  value: string,
  issuerOrigin: string,
  field: string,
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new TypeError(`${field} is not a valid URL`, { cause: error });
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (
    url.protocol !== 'https:' ||
    url.origin !== issuerOrigin ||
    url.username ||
    url.password ||
    isIP(hostname) !== 0
  ) {
    throw new TypeError(`${field} must be an HTTPS URL on the issuer origin`);
  }
  return url.href;
}
