import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Lambda011Adapter } from './lambda-011.adapter.js';

const MISSING_ALARM_FINDING = 'missing-monitoring-alarm';

const FINDINGS = {
  [MISSING_ALARM_FINDING]: {
    issue: 'Lambda functions must have CloudWatch alarms for monitoring',
    remediation: 'Add CloudWatch alarms to monitor key Lambda operational metrics (Errors, Throttles, Duration, ConcurrentExecutions).',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Lambda011Control extends SecurityControl<Lambda011Adapter, FindingKey> {
  constructor() {
    super({
      id: 'LAMBDA-011',
      priority: 'HIGH',
      description: 'Lambda functions must have CloudWatch alarms for monitoring',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Lambda011Adapter): FindingKey | null {
    if (adapter.hasMonitoringAlarm()) return null;
    return MISSING_ALARM_FINDING;
  }
}

export const lambda011Control = new Lambda011Control();
