import type {
  IAttestationsResource,
  ICredentialsResource,
} from '@stripe/link-sdk';
import { sanitizeDeep } from '../../utils/sanitize-text';
import { DEFAULT_AAT_POOL_PATH, saveIssuedTokens } from '../attestations/pool';
import {
  DEFAULT_HOLDER_KEY_PATH,
  type HolderKeyType,
} from '../credentials/holder-key';
import { runIdentityRequest } from '../request/run';
import type { MppIdentityHeaders, MppIdentityProvider } from './pay';

const DEFAULT_ATTESTATION_ISSUER = 'https://api.link.com';
const DEFAULT_ATTESTATION_REFILL = 10;

export interface MppIdentityResources {
  createAttestationsResource: () => IAttestationsResource;
  createCredentialsResource: () => ICredentialsResource;
  issuer?: string;
  poolFile?: string;
  keyFile?: string;
  keyType?: HolderKeyType;
  refillCount?: number;
}

/**
 * Creates the identity side of an MPP request. The caller owns HTTP retries;
 * this provider only answers a response that actually challenged for Link
 * attestation or identity claims.
 */
export function createMppIdentityProvider(options: {
  url: string;
  method?: string;
  data?: string;
  headers?: string[];
  resources: MppIdentityResources;
}): MppIdentityProvider {
  const { url, method, data, headers = [], resources } = options;
  const poolFile = resources.poolFile ?? DEFAULT_AAT_POOL_PATH;
  const keyFile = resources.keyFile ?? DEFAULT_HOLDER_KEY_PATH;
  const keyType = resources.keyType ?? 'ed25519';
  const issuer = resources.issuer ?? DEFAULT_ATTESTATION_ISSUER;
  const refillCount = resources.refillCount ?? DEFAULT_ATTESTATION_REFILL;

  const prepare = async (
    response: Response,
  ): Promise<MppIdentityHeaders | undefined> => {
    const body = await response.clone().text();
    const attempt = () =>
      runIdentityRequest({
        url,
        method,
        data,
        header: headers,
        prepare: true,
        keyFile,
        keyType,
        poolFile,
        createCredentialsResource: resources.createCredentialsResource,
        initialResponse: { response, body },
        sanitizeDeep,
      });

    let result = await attempt();
    if (
      !result.ok &&
      (result.error.code === 'AAT_POOL_EMPTY' ||
        result.error.code === 'AAT_NO_MATCH')
    ) {
      const issued = await resources.createAttestationsResource().request({
        issuer,
        count: refillCount,
      });
      saveIssuedTokens(poolFile, issued);
      result = await attempt();
    }

    if (!result.ok) {
      throw new Error(`${result.error.code}: ${result.error.message}`);
    }

    const prepared = result.value.prepared_headers;
    if (!prepared) return undefined;
    return {
      attestation: prepared.attestation,
      identityPresentation: prepared.identity_presentation,
    };
  };

  return { prepare };
}
