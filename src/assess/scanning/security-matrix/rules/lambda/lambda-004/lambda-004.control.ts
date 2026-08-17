import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Lambda004Adapter } from './lambda-004.adapter.js';
import { lambda012Control } from '../lambda-012/lambda-012.control.js';

const MISSING_TRACING_FINDING = 'missing-tracing-configuration';

const FINDINGS = {
  [MISSING_TRACING_FINDING]: {
    issue: 'Lambda function does not have X-Ray active tracing enabled; tracing must be set to Active mode so the function records trace segments.',
    remediation: 'Enable AWS X-Ray active tracing on the Lambda function so that trace segments are recorded.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Lambda004Control extends SecurityControl<Lambda004Adapter, FindingKey> {
  constructor() {
    super({
      id: 'LAMBDA-004',
      priority: 'HIGH',
      description: 'Lambda functions must have X-Ray tracing enabled',
      findings: FINDINGS,
      relatedRules: [lambda012Control],
    });
  }

  protected evaluate(adapter: Lambda004Adapter): FindingKey | null {
    if (adapter.hasTracingConfigured()) return null;
    return MISSING_TRACING_FINDING;
  }
}

export const lambda004Control = new Lambda004Control();
