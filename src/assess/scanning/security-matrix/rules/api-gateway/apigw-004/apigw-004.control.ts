import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw004Adapter } from './apigw-004.adapter.js';

const MISSING_AUTHORIZATION = 'missing-authorization';

export class Apigw004Control extends SecurityControl<Apigw004Adapter> {
  constructor() {
    super({
      id: 'APIGW-004',
      priority: 'HIGH',
      description: 'API Gateway methods (other than OPTIONS) must have an authorization type of AWS_IAM, COGNITO_USER_POOLS, or CUSTOM configured (with an associated authorizer for CUSTOM or COGNITO_USER_POOLS), and API Gateway APIs must have an authorizer configured rather than allowing unauthenticated access',
      supersedes: ['CKV_AWS_59', 'CKV_AWS_309'],
      remediationScenarios: [
        {
          scenario: MISSING_AUTHORIZATION,
          intent:
            'Require callers to be authorized on this API method by configuring an authorization mode of IAM, Cognito user pools, or a custom authorizer, associating an authorizer where the mode requires one.',
        },
      ],
    });
  }

  protected evaluate(adapter: Apigw004Adapter): ControlFinding | null {
    if (adapter.isOptionsMethod()) return null;
    if (!adapter.hasNoAuthorizationConfiguration()) return null;
    return {
      scenario: MISSING_AUTHORIZATION,
      issue: 'API method allows unauthenticated access because no authorization is configured',
    };
  }
}

export const apigw004Control = new Apigw004Control();
