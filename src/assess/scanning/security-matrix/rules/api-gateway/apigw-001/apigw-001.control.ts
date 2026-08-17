import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Apigw001Adapter } from './apigw-001.adapter.js';

const MISSING_ACCESS_LOGGING_FINDING = 'missing-access-logging';
const MISSING_LOG_RETENTION_FINDING = 'missing-log-retention';

const FINDINGS = {
  [MISSING_ACCESS_LOGGING_FINDING]: {
    issue: 'API Gateway stage does not have access logging configured',
    remediation: 'Enable access logging on the API Gateway stage so that per-request data is captured to a durable log destination with an appropriate retention policy.',
  },
  [MISSING_LOG_RETENTION_FINDING]: {
    issue: 'API Gateway stage access log destination has no retention period configured, causing logs to be retained indefinitely',
    remediation: 'Configure an explicit retention period on the log destination used by the API Gateway stage so access logs are not retained indefinitely.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Apigw001Control extends SecurityControl<Apigw001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'APIGW-001',
      priority: 'HIGH',
      description: 'API Gateways must enable access logging with proper retention',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Apigw001Adapter): FindingKey | null {
    if (!adapter.hasAccessLogging()) return MISSING_ACCESS_LOGGING_FINDING;
    if (!adapter.hasProperLogRetention()) return MISSING_LOG_RETENTION_FINDING;
    return null;
  }
}

export const apigw001Control = new Apigw001Control();
