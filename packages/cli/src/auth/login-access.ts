// Computes the re-login access plan: whether the requested login narrows the
// current session, what to prompt for, and what access to merge back in.
// Callers fold `--source-action` flags into the requested authorization details
// (as a `{ type: 'source', actions }` detail) before calling in, so `source` is
// handled here like any other authorization-detail type.
import { DEFAULT_SCOPE, normalizeScopeInput } from './scopes';
import type { JsonValue } from './types';

const DEFAULT_SCOPE_TOKENS = DEFAULT_SCOPE.split(' ');

interface RawAuthorizationDetail {
  detail: JsonValue;
  type: string;
}

interface RequestedAccessDetails {
  authorizationDetails: JsonValue[];
  requestedTypes: Set<string>;
}

interface GrantedAccessDetail {
  type: string;
  resourceId: string;
  actions: string[];
}

export interface MissingResourceAccess {
  type: string;
  resourceCount: number;
  actions: string[];
}

export interface MissingAuthorizationDetail {
  detailCount: number;
  type?: string;
}

export interface LoginAccessPlan {
  mergedAuthorizationDetails: JsonValue[];
  mergedScope: string;
  missingAuthorizationDetails: MissingAuthorizationDetail[];
  missingResourceAccess: MissingResourceAccess[];
  missingScopes: string[];
  shouldEarlyExit: boolean;
  shouldPrompt: boolean;
}

interface ResolveLoginAccessPlanOptions {
  existingAuthorizationDetails?: readonly JsonValue[];
  existingScope?: string;
  requestedAuthorizationDetails?: readonly JsonValue[];
  requestedScope?: string;
}

// Dedupe while keeping first-seen order (Set alone would reorder nothing, but
// this also yields a plain array for downstream use).
function dedupePreserveOrder<T>(values: readonly T[]): T[] {
  const seen = new Set<T>();
  const deduped: T[] = [];

  for (const value of values) {
    if (seen.has(value)) {
      continue;
    }

    seen.add(value);
    deduped.push(value);
  }

  return deduped;
}

// Concatenate then dedupe: `current` entries win their position over dupes.
function unionPreserveOrder<T>(
  current: readonly T[],
  additional: readonly T[],
): T[] {
  return dedupePreserveOrder([...current, ...additional]);
}

// Narrow a JsonValue to a plain object (not null, not an array).
function isRecord(value: JsonValue): value is Record<string, JsonValue> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Safely read the string `type` field off an authorization detail, if present.
function getDetailType(detail: JsonValue): string | undefined {
  if (!isRecord(detail) || typeof detail.type !== 'string') {
    return undefined;
  }

  return detail.type;
}

// Return the value as a string[] only if it's an array of all strings, else null.
function getStringArray(value: JsonValue | undefined): string[] | null {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    return null;
  }

  return value as string[];
}

// Turn a space-delimited scope string into individual tokens. When the input
// is empty/absent, fall back to the default scope so that an unspecified
// request is compared against the same baseline the server would grant.
function normalizeScopeTokens(
  scope: string | undefined,
  fallbackToDefault: boolean,
): string[] {
  const normalized = normalizeScopeInput(scope);
  if (normalized) {
    return normalized.split(' ');
  }

  return fallbackToDefault ? [...DEFAULT_SCOPE_TOKENS] : [];
}

// Parse a previously-granted authorization detail into a normalized shape we
// can compare against. Returns null when the detail doesn't fit the expected
// { type, actions } record — such details are treated as opaque "raw" details
// elsewhere. Details without a resource_id get a synthetic per-index id so each
// standing grant still counts as a distinct resource.
function parseGrantedAccessDetail(
  detail: JsonValue,
  index: number,
): GrantedAccessDetail | null {
  if (!isRecord(detail)) {
    return null;
  }

  const type = typeof detail.type === 'string' ? detail.type : null;
  const actions = getStringArray(detail.actions);
  if (!type || !actions) {
    return null;
  }

  return {
    type,
    resourceId:
      typeof detail.resource_id === 'string'
        ? detail.resource_id
        : `__standing__:${index}`,
    actions: dedupePreserveOrder(actions),
  };
}

// Collect the set of authorization-detail *types* being requested this login,
// so the main pass can tell which existing types are still covered.
function parseRequestedAccessDetails(
  requestedAuthorizationDetails: readonly JsonValue[] | undefined,
): RequestedAccessDetails {
  const requestedTypes = new Set<string>();

  for (const detail of requestedAuthorizationDetails ?? []) {
    const type = getDetailType(detail);
    if (type) {
      requestedTypes.add(type);
    }
  }

  return {
    authorizationDetails: [...(requestedAuthorizationDetails ?? [])],
    requestedTypes,
  };
}

// Join items into a natural-language list ("a", "a and b", "a, b, and c").
function formatList(items: readonly string[]): string {
  if (items.length <= 1) {
    return items[0] ?? '';
  }

  if (items.length === 2) {
    return `${items[0]} and ${items[1]}`;
  }

  return `${items.slice(0, -1).join(', ')}, and ${items[items.length - 1]}`;
}

// Build the final authorization details to send on the (re-)login: the
// requested details plus anything the requested login would have dropped.
function buildMergedAuthorizationDetails(
  requestedDetails: RequestedAccessDetails,
  missingActionsByType: Map<string, string[]>,
  missingRawDetails: readonly RawAuthorizationDetail[],
): JsonValue[] {
  const authorizationDetails = [...requestedDetails.authorizationDetails];

  // Re-add opaque details verbatim, then re-add parsed details rebuilt from the
  // missing actions grouped by type.
  for (const missingRawDetail of missingRawDetails) {
    authorizationDetails.push(missingRawDetail.detail);
  }

  for (const [type, actions] of missingActionsByType) {
    authorizationDetails.push({ type, actions });
  }

  return authorizationDetails;
}

function hasRequestedAuthorizationDetailType(
  requestedDetails: RequestedAccessDetails,
  type: string,
): boolean {
  return requestedDetails.requestedTypes.has(type);
}

// Collapse the opaque missing details into per-type counts for the user-facing
// prompt (e.g. "2 authorization details of type X").
function summarizeMissingAuthorizationDetails(
  missingRawDetails: readonly RawAuthorizationDetail[],
): MissingAuthorizationDetail[] {
  const countsByType = new Map<string, number>();

  for (const missingRawDetail of missingRawDetails) {
    countsByType.set(
      missingRawDetail.type,
      (countsByType.get(missingRawDetail.type) ?? 0) + 1,
    );
  }

  const summarized = [...countsByType.entries()].map(([type, detailCount]) => ({
    type,
    detailCount,
  }));

  return summarized;
}

// Core planner: compare the requested login against the current session and
// decide (a) whether the request narrows access, (b) what to tell the user, and
// (c) the superset access to actually send if they accept.
export function resolveLoginAccessPlan({
  requestedScope,
  requestedAuthorizationDetails,
  existingScope,
  existingAuthorizationDetails,
}: ResolveLoginAccessPlanOptions): LoginAccessPlan {
  const requestedScopeTokens = normalizeScopeTokens(requestedScope, true);
  const existingScopeTokens = normalizeScopeTokens(existingScope, true);
  const requestedDetails = parseRequestedAccessDetails(
    requestedAuthorizationDetails,
  );
  // Accumulators for existing access the request would drop, keyed by type:
  //   - missingActionsByType: which actions would be lost per type
  //   - missingResourcesByType: distinct resources affected per type (for counts)
  //   - missingRawDetails: opaque details we couldn't parse, kept verbatim
  const missingActionsByType = new Map<string, string[]>();
  const missingResourcesByType = new Map<string, Set<string>>();
  const missingRawDetails: RawAuthorizationDetail[] = [];

  // Walk every existing authorization detail and record the ones the request
  // wouldn't cover. Coverage is coarse: if the request asks for the same
  // *type* at all, the existing detail of that type is considered covered.
  (existingAuthorizationDetails ?? []).forEach((detail, index) => {
    const detailType = getDetailType(detail);
    if (
      detailType &&
      hasRequestedAuthorizationDetailType(requestedDetails, detailType)
    ) {
      return;
    }

    const grantedDetail = parseGrantedAccessDetail(detail, index);
    // Unparseable detail: can't reason about its actions, so preserve it as-is.
    if (!grantedDetail) {
      missingRawDetails.push({
        detail,
        type: detailType || '',
      });
      return;
    }

    // Record the lost actions and the affected resource for this type.
    missingActionsByType.set(
      grantedDetail.type,
      unionPreserveOrder(
        missingActionsByType.get(grantedDetail.type) ?? [],
        grantedDetail.actions,
      ),
    );

    const missingResources =
      missingResourcesByType.get(grantedDetail.type) ?? new Set<string>();
    missingResources.add(grantedDetail.resourceId);
    missingResourcesByType.set(grantedDetail.type, missingResources);
  });

  // Scope tokens present in the existing session but absent from the request.
  const missingScopes = existingScopeTokens.filter(
    (scopeToken) => !requestedScopeTokens.includes(scopeToken),
  );
  // Shape the parsed losses into the resource-access summary for the prompt.
  const missingResourceAccess = [...missingResourcesByType.entries()].map(
    ([type, resourceIds]) => ({
      type,
      resourceCount: resourceIds.size,
      actions: missingActionsByType.get(type) ?? [],
    }),
  );
  const missingAuthorizationDetails =
    summarizeMissingAuthorizationDetails(missingRawDetails);

  // Early exit: neither side has authorization details and the scopes match
  // exactly, so there's nothing to compare — proceed with the plain login.
  const hasRequestedAuthorizationDetails =
    (requestedAuthorizationDetails?.length ?? 0) > 0;
  const hasExistingAuthorizationDetails =
    (existingAuthorizationDetails?.length ?? 0) > 0;
  const shouldEarlyExit =
    !hasRequestedAuthorizationDetails &&
    !hasExistingAuthorizationDetails &&
    missingScopes.length === 0 &&
    existingScopeTokens.length === requestedScopeTokens.length;
  // Prompt the user whenever the request would drop any existing access.
  const shouldPrompt =
    missingScopes.length > 0 ||
    missingResourceAccess.length > 0 ||
    missingAuthorizationDetails.length > 0;
  // Superset to send if the user accepts: requested access + everything missing.
  const mergedScope = unionPreserveOrder(
    requestedScopeTokens,
    missingScopes,
  ).join(' ');
  const mergedAuthorizationDetails = buildMergedAuthorizationDetails(
    requestedDetails,
    missingActionsByType,
    missingRawDetails,
  );

  return {
    mergedAuthorizationDetails,
    mergedScope,
    missingAuthorizationDetails,
    missingResourceAccess,
    missingScopes,
    shouldEarlyExit,
    shouldPrompt,
  };
}

// Render the human-facing confirmation prompt describing what the requested
// login would remove and asking whether to add it back to the request.
export function formatLoginAccessPrompt(plan: LoginAccessPlan): string {
  // Build one phrase per category of lost access, then join into one sentence.
  const losses: string[] = [];

  if (plan.missingScopes.length > 0) {
    losses.push(`your access to ${formatList(plan.missingScopes)}`);
  }

  if (plan.missingResourceAccess.length > 0) {
    losses.push(
      plan.missingResourceAccess
        .map(
          ({ resourceCount, type }) =>
            `your access to ${resourceCount} ${resourceCount === 1 ? 'resource' : 'resources'} of type ${type}`,
        )
        .join(' and '),
    );
  }

  if (plan.missingAuthorizationDetails.length > 0) {
    losses.push(
      plan.missingAuthorizationDetails
        .map(
          ({ detailCount, type }) =>
            `your access requested via ${detailCount} authorization ${detailCount === 1 ? 'detail' : 'details'}${type ? ` of type ${type}` : ''}`,
        )
        .join(' and '),
    );
  }

  // "them" when more than one distinct thing would be lost, otherwise "it".
  const noun =
    plan.missingScopes.length +
      plan.missingResourceAccess.length +
      plan.missingAuthorizationDetails.length >
    1
      ? 'them'
      : 'it';
  return `Your requested login would remove ${formatList(losses)}. Do you want to add ${noun} to your request?`;
}
