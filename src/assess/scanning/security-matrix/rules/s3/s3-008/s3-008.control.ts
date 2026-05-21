import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { S3008Adapter } from './s3-008.adapter.js';

export class S3008Control extends SecurityControl<S3008Adapter> {
  constructor() {
    super({
      id: 'S3-008',
      priority: 'HIGH',
      description: 'S3 buckets must have a lifecycle policy',
      remediationScenarios: [
        {
          scenario: 'missing-lifecycle-configuration',
          intent: 'Configure a lifecycle policy for the S3 bucket that transitions objects to STANDARD_IA after 30 days.',
        },
      ],
    });
  }

  protected evaluate(adapter: S3008Adapter): ControlFinding | null {
    if (!adapter.isBucket) return null;
    if (adapter.hasLifecycleConfiguration) return null;
    return { scenario: 'missing-lifecycle-configuration' };
  }
}

export const s3008Control = new S3008Control();
