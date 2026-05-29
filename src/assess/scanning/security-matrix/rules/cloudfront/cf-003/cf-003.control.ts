import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf003Adapter } from './cf-003.adapter.js';

const NO_LOGGING_SCENARIO = 'no-access-logging';

export class Cf003Control extends SecurityControl<Cf003Adapter> {
  constructor() {
    super({
      id: 'CF-003',
      priority: 'HIGH',
      description: 'CloudFront distributions must enable access logging',
      remediationScenarios: [
        {
          scenario: NO_LOGGING_SCENARIO,
          intent:
            'Enable access logging for the CloudFront distribution so that viewer requests are captured, either by configuring inline standard logging on the distribution or by wiring a complete dedicated log delivery pipeline (both source and destination) that targets it.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf003Adapter): ControlFinding | null {
    if (!adapter.hasAccessLogging) {
      return {
        scenario: NO_LOGGING_SCENARIO,
        issue:
          'CloudFront distribution does not have a complete access logging configuration: neither inline access logging is configured nor a complete external log delivery pipeline (source paired with destination) is defined for it',
      };
    }
    return null;
  }
}

export const cf003Control = new Cf003Control();
