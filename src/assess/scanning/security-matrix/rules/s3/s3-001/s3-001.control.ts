import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { S3001Adapter } from './s3-001.adapter.js';
import { s3008Control } from '../s3-008/s3-008.control.js';

const MISSING_ACCESS_LOGGING = 'enable-server-access-logging';

const FINDINGS = {
  [MISSING_ACCESS_LOGGING]: {
    issue: 'S3 bucket has no server access logging configured and is not used as a log destination by another bucket',
    remediation: 'Enable server access logging on the S3 bucket by configuring it to deliver access logs to a designated log destination bucket.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class S3001Control extends SecurityControl<S3001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'S3-001',
      priority: 'HIGH',
      description: 'S3 buckets must enable server access logging unless serving as a log destination',
      findings: FINDINGS,
      relatedRules: [s3008Control],
    });
  }

  protected evaluate(adapter: S3001Adapter): FindingKey | null {
    if (adapter.hasLoggingConfigured()) return null;
    if (adapter.isLogDestination()) return null;
    return MISSING_ACCESS_LOGGING;
  }
}

export const s3001Control = new S3001Control();
