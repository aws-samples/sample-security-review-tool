import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { S3001Adapter } from './s3-001.adapter.js';

export class S3001Control extends SecurityControl<S3001Adapter> {
  constructor() {
    super({
      id: 'S3-001',
      priority: 'HIGH',
      description: 'S3 buckets must enable server access logging unless serving as a log destination',
      remediationScenarios: [
        {
          scenario: 'enable-server-access-logging',
          intent: 'Enable server access logging on the S3 bucket by configuring a target log destination bucket.',
        },
      ],
    });
  }

  protected evaluate(adapter: S3001Adapter): ControlFinding | null {
    if (adapter.hasServerAccessLogging()) return null;
    if (adapter.isLogDestination()) return null;
    return {
      scenario: 'enable-server-access-logging',
      issue: 'S3 bucket has no server access logging configured and is not referenced as a log destination by any other bucket in the template',
    };
  }
}

export const s3001Control = new S3001Control();
