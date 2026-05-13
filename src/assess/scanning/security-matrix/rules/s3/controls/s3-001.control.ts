import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { S3BucketAdapter } from '../adapters/s3-bucket-adapter.js';

export class S3001Control extends SecurityControl<S3BucketAdapter> {
  constructor() {
    super({
      id: 'S3-001',
      priority: 'HIGH',
      description: 'S3 bucket lacks proper access logging configuration',
      remediationScenarios: [
        { scenario: 'missing-logging', intent: 'Enable S3 access logging with a separate dedicated logging bucket.' },
        { scenario: 'self-logging', intent: 'Redirect access logs to a separate dedicated logging bucket instead of self-logging.' },
      ],
    });
  }

  protected evaluate(adapter: S3BucketAdapter): ControlFinding | null {
    if (adapter.isLogDestinationBucket()) return null;
    if (!adapter.getLoggingDestination()) return { scenario: 'missing-logging' };
    if (adapter.isSelfLogging()) return { scenario: 'self-logging' };
    return null;
  }
}

export const s3001Control = new S3001Control();
