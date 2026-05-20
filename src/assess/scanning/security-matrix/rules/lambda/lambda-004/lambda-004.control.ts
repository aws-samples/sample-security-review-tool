import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lambda004Adapter } from './lambda-004.adapter.js';

const MISSING_TRACING_SCENARIO = 'missing-tracing-configuration';

export class Lambda004Control extends SecurityControl<Lambda004Adapter> {
  constructor() {
    super({
      id: 'LAMBDA-004',
      priority: 'HIGH',
      description: 'Lambda functions must have X-Ray tracing enabled',
      remediationScenarios: [
        {
          scenario: MISSING_TRACING_SCENARIO,
          intent: 'Enable AWS X-Ray active tracing on the Lambda function so that trace segments are recorded.',
        },
      ],
    });
  }

  protected evaluate(adapter: Lambda004Adapter): ControlFinding | null {
    if (adapter.hasTracingConfigured()) {
      return null;
    }
    return {
      scenario: MISSING_TRACING_SCENARIO,
      issue: 'Lambda function does not have X-Ray active tracing enabled; tracing must be set to Active mode so the function records trace segments.',
    };
  }
}

export const lambda004Control = new Lambda004Control();
