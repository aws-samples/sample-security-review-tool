import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Cf003Adapter } from './cf-003.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

const NO_LOGGING_FINDING = 'no-access-logging';

const FINDINGS = {
  [NO_LOGGING_FINDING]: {
    issue: 'CloudFront distribution does not have a complete access logging configuration: neither inline access logging is configured nor a complete external log delivery pipeline (source paired with destination) is defined for it',
    remediation: 'Enable access logging for the CloudFront distribution so that viewer requests are captured, either by configuring inline standard logging on the distribution or by wiring a complete dedicated log delivery pipeline (both source and destination) that targets it.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Cf003Control extends SecurityControl<Cf003Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CF-003',
      priority: 'HIGH',
      description: 'CloudFront distributions must enable access logging',
      findings: FINDINGS,
      relatedRules: [s3001Control, s3008Control],
    });
  }

  protected evaluate(adapter: Cf003Adapter): FindingKey | null {
    if (!adapter.hasAccessLogging) return NO_LOGGING_FINDING;
    return null;
  }
}

export const cf003Control = new Cf003Control();
