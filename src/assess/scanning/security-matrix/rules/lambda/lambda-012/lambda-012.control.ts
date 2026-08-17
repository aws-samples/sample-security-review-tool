import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Lambda012Adapter } from './lambda-012.adapter.js';

const SHARED_ROLE_FINDING = 'shared-execution-role';

const FINDINGS = {
  [SHARED_ROLE_FINDING]: {
    issue: 'This Lambda function shares its IAM execution role with another resource in the same template.',
    remediation: 'Give each Lambda function its own dedicated IAM execution role scoped to only the permissions that function needs.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Lambda012Control extends SecurityControl<Lambda012Adapter, FindingKey> {
  constructor() {
    super({
      id: 'LAMBDA-012',
      priority: 'HIGH',
      description: 'Lambda functions must have unique IAM execution roles',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Lambda012Adapter): FindingKey | null {
    if (!adapter.sharesExecutionRole) return null;
    return SHARED_ROLE_FINDING;
  }
}

export const lambda012Control = new Lambda012Control();
