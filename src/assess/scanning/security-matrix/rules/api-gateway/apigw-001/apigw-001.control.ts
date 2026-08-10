import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Apigw001Adapter } from './apigw-001.adapter.js';

const MISSING_ACCESS_LOGGING_SCENARIO = 'missing-access-logging';
const MISSING_LOG_RETENTION_SCENARIO = 'missing-log-retention';

export class Apigw001Control extends SecurityControl<Apigw001Adapter> {
  constructor() {
    super({
      id: 'APIGW-001',
      priority: 'HIGH',
      description: 'API Gateways must enable access logging with proper retention',
      remediationScenarios: [
        {
          scenario: MISSING_ACCESS_LOGGING_SCENARIO,
          intent: 'Enable access logging on the API Gateway stage so that per-request data is captured to a durable log destination with an appropriate retention policy.',
        },
        {
          scenario: MISSING_LOG_RETENTION_SCENARIO,
          intent: 'Configure an explicit retention period on the log destination used by the API Gateway stage so access logs are not retained indefinitely.',
        },
      ],
    });
  }

  protected evaluate(adapter: Apigw001Adapter): ControlFinding | null {
    if (!adapter.hasAccessLogging()) {
      return {
        scenario: MISSING_ACCESS_LOGGING_SCENARIO,
        issue: 'API Gateway stage does not have access logging configured',
      };
    }
    if (!adapter.hasProperLogRetention()) {
      return {
        scenario: MISSING_LOG_RETENTION_SCENARIO,
        issue: 'API Gateway stage access log destination has no retention period configured, causing logs to be retained indefinitely',
      };
    }
    return null;
  }
}

export const apigw001Control = new Apigw001Control();
