import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf004Adapter } from './cf-004.adapter.js';

const MISSING_VIEWER_PROTOCOL_POLICY_SCENARIO = 'missing-default-viewer-protocol-policy';
const ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_SCENARIO = 'default-viewer-protocol-policy-allows-http';
const ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_SCENARIO = 'additional-cache-behavior-allows-http';

export class Cf004Control extends SecurityControl<Cf004Adapter> {
  constructor() {
    super({
      id: 'CF-004',
      priority: 'HIGH',
      description: 'CloudFront distributions must only accept traffic over HTTPS',
      remediationScenarios: [
        {
          scenario: MISSING_VIEWER_PROTOCOL_POLICY_SCENARIO,
          intent: 'Enforce HTTPS on the distribution default cache behavior by requiring viewers to use HTTPS or be redirected to HTTPS.',
        },
        {
          scenario: ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_SCENARIO,
          intent: 'Restrict the distribution default cache behavior so that viewers can only connect over HTTPS, either by requiring HTTPS or by redirecting HTTP requests to HTTPS.',
        },
        {
          scenario: ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_SCENARIO,
          intent: 'Restrict every additional cache behavior so that viewers can only connect over HTTPS, either by requiring HTTPS or by redirecting HTTP requests to HTTPS.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf004Adapter): ControlFinding | null {
    if (!adapter.hasDefaultCacheBehaviorViewerProtocolPolicy()) {
      return {
        scenario: MISSING_VIEWER_PROTOCOL_POLICY_SCENARIO,
        issue: 'CloudFront distribution default cache behavior does not specify a viewer protocol policy, allowing plaintext HTTP traffic.',
      };
    }

    if (adapter.defaultCacheBehaviorAllowsHttp()) {
      return {
        scenario: ALLOW_HTTP_VIEWER_PROTOCOL_POLICY_SCENARIO,
        issue: 'CloudFront distribution default cache behavior permits unencrypted HTTP traffic from viewers.',
      };
    }

    if (adapter.hasAdditionalCacheBehaviorAllowingHttp()) {
      return {
        scenario: ADDITIONAL_BEHAVIOR_ALLOWS_HTTP_SCENARIO,
        issue: 'CloudFront distribution has an additional cache behavior that permits unencrypted HTTP traffic from viewers for its matched path pattern.',
      };
    }

    return null;
  }
}

export const cf004Control = new Cf004Control();
