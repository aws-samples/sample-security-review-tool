import { Stack, StackProps } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

/**
 * Fixture stack for CF-003: CloudFront distributions must enable access logging.
 *
 * Scenarios triggered:
 *  - no-access-logging: A CloudFront distribution is created without inline
 *    access logging and without any external CloudWatch Logs delivery
 *    pipeline (no DeliverySource referencing it, no DeliveryDestination,
 *    and no MonitoringSubscription). The adapter should detect that the
 *    distribution has no complete logging configuration.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Origin bucket for the distribution. This bucket is purely an origin
    // and is intentionally NOT used as a CloudFront access log target.
    const originBucket = new s3.Bucket(this, 'OriginBucket');

    // Scenario: no-access-logging
    // CloudFront distribution with no logging configuration at all.
    new cloudfront.Distribution(this, 'NoLoggingDistribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(originBucket),
      },
      // No `logFilePrefix`, `logBucket`, or `enableLogging` — inline logging is absent.
      // No accompanying AWS::Logs::DeliverySource / DeliveryDestination /
      // MonitoringSubscription resources are defined in this stack, so the
      // external delivery chain is incomplete as well.
    });
  }
}
