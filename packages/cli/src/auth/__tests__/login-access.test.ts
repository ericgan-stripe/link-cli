import { describe, expect, it } from 'vitest';
import {
  formatLoginAccessPrompt,
  resolveLoginAccessPlan,
} from '../login-access';
import type { JsonValue } from '../types';

describe('resolveLoginAccessPlan', () => {
  it('early exits only for identical scope-only access', () => {
    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [],
    });

    expect(plan.shouldEarlyExit).toBe(true);
    expect(plan.shouldPrompt).toBe(false);
    expect(plan.missingScopes).toEqual([]);
    expect(plan.missingResourceAccess).toEqual([]);
  });

  it('does not early exit when authorization details are involved, even if access matches', () => {
    const requestedSourceDetail: JsonValue = {
      type: 'source',
      actions: ['read_source_details'],
    };
    const existingAuthorizationDetails: JsonValue[] = [
      {
        type: 'source',
        resource_id: 'src_123',
        actions: ['read_source_details'],
      },
    ];

    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [requestedSourceDetail],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails,
    });

    expect(plan.shouldEarlyExit).toBe(false);
    expect(plan.shouldPrompt).toBe(false);
    expect(plan.mergedAuthorizationDetails).toEqual([requestedSourceDetail]);
  });

  it('does not treat comma-delimited stored scopes as removed access', () => {
    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [
        { type: 'source', actions: ['read_link_transactions'] },
      ],
      existingScope: 'userinfo:read,payment_methods.agentic',
      existingAuthorizationDetails: [],
    });

    expect(plan.shouldEarlyExit).toBe(false);
    expect(plan.shouldPrompt).toBe(false);
    expect(plan.missingScopes).toEqual([]);
  });

  it('treats explicit authorization detail types as covered access for the downgrade check', () => {
    const explicitDetail = {
      type: 'account',
      filters: ['current'],
    };

    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [explicitDetail],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [
        {
          type: 'account',
          resource_id: 'acct_123',
          actions: ['read'],
        },
      ],
    });

    expect(plan.shouldPrompt).toBe(false);
    expect(plan.missingResourceAccess).toEqual([]);
    expect(plan.missingAuthorizationDetails).toEqual([]);
    expect(plan.mergedAuthorizationDetails).toEqual([explicitDetail]);
  });

  it('detects missing scopes even when requested source access is narrower', () => {
    const requestedSourceDetail: JsonValue = {
      type: 'source',
      actions: ['read_source_details'],
    };
    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read',
      requestedAuthorizationDetails: [requestedSourceDetail],
      existingScope:
        'userinfo:read payment_methods.agentic spend_requests:approve',
      existingAuthorizationDetails: [
        {
          type: 'source',
          resource_id: 'src_123',
          actions: ['read_source_details', 'read_balances'],
        },
        {
          type: 'source',
          resource_id: 'src_456',
          actions: ['read_link_transactions'],
        },
      ],
    });

    expect(plan.shouldEarlyExit).toBe(false);
    expect(plan.shouldPrompt).toBe(true);
    expect(plan.missingScopes).toEqual([
      'payment_methods.agentic',
      'spend_requests:approve',
    ]);
    expect(plan.missingResourceAccess).toEqual([]);
    expect(plan.mergedScope).toBe(
      'userinfo:read payment_methods.agentic spend_requests:approve',
    );
    expect(plan.mergedAuthorizationDetails).toEqual([requestedSourceDetail]);
    expect(formatLoginAccessPrompt(plan)).not.toContain(
      'resources of type source',
    );
  });

  it('prompts to preserve non-action authorization details and merges them exactly', () => {
    const existingDetail = {
      type: 'account',
      filters: ['current'],
    };

    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [existingDetail],
    });

    expect(plan.shouldPrompt).toBe(true);
    expect(plan.mergedAuthorizationDetails).toEqual([existingDetail]);
    expect(formatLoginAccessPrompt(plan)).toContain(
      '1 authorization detail of type account',
    );
  });

  it('prompts when no requested authorization detail type covers existing source access', () => {
    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [
        {
          type: 'source',
          resource_id: 'src_123',
          actions: ['read_source_details'],
        },
      ],
    });

    expect(plan.shouldPrompt).toBe(true);
    expect(plan.missingResourceAccess).toEqual([
      {
        type: 'source',
        resourceCount: 1,
        actions: ['read_source_details'],
      },
    ]);
  });

  it('still prompts for missing scopes when explicit authorization details are provided', () => {
    const explicitDetail = {
      type: 'account',
      filters: ['current'],
    };

    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read',
      requestedAuthorizationDetails: [explicitDetail],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [
        {
          type: 'account',
          resource_id: 'acct_123',
          actions: ['read'],
        },
      ],
    });

    expect(plan.shouldPrompt).toBe(true);
    expect(plan.missingScopes).toEqual(['payment_methods.agentic']);
    expect(plan.missingResourceAccess).toEqual([]);
    expect(plan.missingAuthorizationDetails).toEqual([]);
    expect(plan.mergedScope).toBe('userinfo:read payment_methods.agentic');
    expect(plan.mergedAuthorizationDetails).toEqual([explicitDetail]);
  });

  it('preserves explicit non-source authorization details and passthrough entries', () => {
    const passthrough = {
      type: 'account',
      filters: ['current'],
    };

    const plan = resolveLoginAccessPlan({
      requestedScope: 'userinfo:read payment_methods.agentic',
      requestedAuthorizationDetails: [
        {
          type: 'account',
          actions: ['transfer'],
        },
        passthrough,
        true,
      ],
      existingScope: 'userinfo:read payment_methods.agentic',
      existingAuthorizationDetails: [
        {
          type: 'account',
          resource_id: 'acct_123',
          actions: ['read'],
        },
      ],
    });

    expect(plan.shouldPrompt).toBe(false);
    expect(plan.missingResourceAccess).toEqual([]);
    expect(plan.missingAuthorizationDetails).toEqual([]);
    expect(plan.mergedAuthorizationDetails).toEqual([
      {
        type: 'account',
        actions: ['transfer'],
      },
      passthrough,
      true,
    ]);
  });
});
