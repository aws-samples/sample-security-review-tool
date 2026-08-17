import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Cf004Adapter } from './cf-004.adapter.js';

const MISSING_VIEWER_PROTOCOL_POLICY_FINDING = 'missing-default-viewer-protocol-policy';
const ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_FINDING = 'default-viewer-protocol-policy-allows-http';
const ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_FINDING = 'additional-cache-behavior-allows-http';

const FINDINGS = {
  [MISSING_VIEWER_PROTOCOL_POLICY_FINDING]: {
    issue: 'CloudFront distribution default cache behavior does not specify a viewer protocol policy, allowing plaintext HTTP traffic.',
    remediation: 'Enforce HTTPS on the distribution default cache behavior by requiring viewers to use HTTPS or be redirected to HTTPS.',
  },
  [ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_FINDING]: {
    issue: 'CloudFront distribution default cache behavior permits unencrypted HTTP traffic from viewers.',
    remediation: 'Restrict the distribution default cache behavior so that viewers can only connect over HTTPS, either by requiring HTTPS or by redirecting HTTP requests to HTTPS.',
  },
  [ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_FINDING]: {
    issue: 'CloudFront distribution has an additional cache behavior that permits unencrypted HTTP traffic from viewers for its matched path pattern.',
    remediation: 'Restrict every additional cache behavior so that viewers can only connect over HTTPS, either by requiring HTTPS or by redirecting HTTP requests to HTTPS.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Cf004Control extends SecurityControl<Cf004Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CF-004',
      priority: 'HIGH',
      description: 'CloudFront distributions must only accept traffic over HTTPS',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Cf004Adapter): FindingKey | null {
    if (!adapter.hasDefaultCacheBehaviorViewerProtocolPolicy()) return MISSING_VIEWER_PROTOCOL_POLICY_FINDING;

    if (adapter.defaultCacheBehaviorAllowsHttp()) return ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_FINDING;

    if (adapter.hasAdditionalCacheBehaviorAllowingHttp()) return ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_FINDING;

    return null;
  }
}

export const cf004Control = new Cf004Control();
