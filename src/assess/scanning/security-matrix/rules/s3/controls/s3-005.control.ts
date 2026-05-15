import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { S3Adapter } from '../adapters/s3-adapter.js';

export class S3005Control extends SecurityControl<S3Adapter> {
  constructor() {
    super({
      id: 'S3-005',
      priority: 'HIGH',
      description: 'CloudFront Origin buckets must enforce access restriction',
      remediationScenarios: [],
    });
  }

  protected evaluate(adapter: S3Adapter): ControlFinding | null {
    return null;
  }
}

export const s3005Control = new S3005Control();
