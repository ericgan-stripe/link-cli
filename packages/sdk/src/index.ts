export { default, Link } from './client';
export type { LinkOptions, LinkSdkLogger } from './config';
export {
  LinkApiError,
  LinkConfigurationError,
  LinkResponseError,
  LinkSdkError,
  LinkTransportError,
} from './errors';
export * from './types/index';
export * from './resources/interfaces';
export * from './resources/attestations';
export * from './resources/credentials';
export { getDuplicateSpendRequest } from './resources/spend-request';
