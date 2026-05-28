import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lambda012Adapter } from './lambda-012.adapter.js';

const SHARED_ROLE_SCENARIO = 'shared-execution-role';

export class Lambda012Control extends SecurityControl<Lambda012Adapter> {
  constructor() {
    super({
      id: 'LAMBDA-012',
      priority: 'HIGH',
      description: 'Lambda functions must have unique IAM execution roles',
      remediationScenarios: [
        {
          scenario: SHARED_ROLE_SCENARIO,
          intent: 'Give each Lambda function its own dedicated IAM execution role scoped to only the permissions that function needs.',
        },
      ],
    });
  }

  protected evaluate(adapter: Lambda012Adapter): ControlFinding | null {
    if (!adapter.sharesExecutionRole) return null;
    return {
      scenario: SHARED_ROLE_SCENARIO,
      issue: 'This Lambda function shares its IAM execution role with another resource in the same template.',
    };
  }
}

export const lambda012Control = new Lambda012Control();
