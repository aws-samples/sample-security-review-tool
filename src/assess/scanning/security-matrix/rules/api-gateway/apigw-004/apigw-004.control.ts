import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Apigw004Adapter } from './apigw-004.adapter.js';

const MISSING_AUTHORIZATION = 'missing-authorization';

const FINDINGS = {
  [MISSING_AUTHORIZATION]: {
    issue: 'API method allows unauthenticated access because no authorization is configured',
    remediation: 'Require callers to be authorized on this API method by configuring an authorization mode of IAM, Cognito user pools, or a custom authorizer, associating an authorizer where the mode requires one.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Apigw004Control extends SecurityControl<Apigw004Adapter, FindingKey> {
  constructor() {
    super({
      id: 'APIGW-004',
      priority: 'HIGH',
      description: 'API Gateway methods (other than OPTIONS) must have an authorization type of AWS_IAM, COGNITO_USER_POOLS, or CUSTOM configured (with an associated authorizer for CUSTOM or COGNITO_USER_POOLS), and API Gateway APIs must have an authorizer configured rather than allowing unauthenticated access',
      supersedes: ['CKV_AWS_59', 'CKV_AWS_309'],
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Apigw004Adapter): FindingKey | null {
    if (adapter.isOptionsMethod()) return null;
    if (adapter.isWebSocketRouteWithoutAuthorizationSupport()) return null;
    if (!adapter.hasNoAuthorizationConfiguration()) return null;
    return MISSING_AUTHORIZATION;
  }
}

export const apigw004Control = new Apigw004Control();
