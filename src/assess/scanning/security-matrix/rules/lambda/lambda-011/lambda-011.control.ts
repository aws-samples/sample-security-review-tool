import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Lambda011Adapter } from './lambda-011.adapter.js';

const MISSING_ALARM_SCENARIO = 'missing-monitoring-alarm';

export class Lambda011Control extends SecurityControl<Lambda011Adapter> {
  constructor() {
    super({
      id: 'LAMBDA-011',
      priority: 'HIGH',
      description: 'Lambda functions must have CloudWatch alarms for monitoring',
      remediationScenarios: [
        {
          scenario: MISSING_ALARM_SCENARIO,
          intent: 'Add CloudWatch alarms to monitor key Lambda operational metrics (Errors, Throttles, Duration, ConcurrentExecutions).',
        },
      ],
    });
  }

  protected evaluate(adapter: Lambda011Adapter): ControlFinding | null {
    if (adapter.hasMonitoringAlarm()) return null;
    return { scenario: MISSING_ALARM_SCENARIO };
  }
}

export const lambda011Control = new Lambda011Control();
