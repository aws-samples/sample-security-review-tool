import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { S3008Adapter } from './s3-008.adapter.js';

const MISSING_LIFECYCLE_CONFIGURATION = 'missing-lifecycle-configuration';

const FINDINGS = {
  [MISSING_LIFECYCLE_CONFIGURATION]: {
    issue: 'S3 buckets must have a lifecycle policy',
    remediation: 'Configure a lifecycle policy for the S3 bucket that transitions objects to STANDARD_IA after 30 days.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class S3008Control extends SecurityControl<S3008Adapter, FindingKey> {
  constructor() {
    super({
      id: 'S3-008',
      priority: 'HIGH',
      description: 'S3 buckets must have a lifecycle policy',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: S3008Adapter): FindingKey | null {
    if (!adapter.isBucket) return null;
    if (adapter.hasLifecycleConfiguration) return null;
    return MISSING_LIFECYCLE_CONFIGURATION;
  }
}

export const s3008Control = new S3008Control();
