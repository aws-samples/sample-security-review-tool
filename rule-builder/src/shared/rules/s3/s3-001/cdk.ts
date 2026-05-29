import { Stack, StackProps } from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

/**
 * Fixture for S3-001: S3 buckets must enable server access logging unless
 * serving as a log destination.
 *
 * Remediation scenarios covered:
 *  - enable-server-access-logging: A bucket with no LoggingConfiguration that
 *    is also not referenced as a log destination by any other bucket in the
 *    template should be flagged.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Non-compliant bucket: no server access logging configured, and no other
    // bucket targets it as a logging destination. This triggers the
    // "enable-server-access-logging" scenario.
    new s3.Bucket(this, 'NonCompliantBucket');
  }
}
