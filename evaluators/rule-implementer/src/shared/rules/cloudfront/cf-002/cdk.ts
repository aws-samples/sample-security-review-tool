import { Stack, StackProps } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

/**
 * Fixture stack for CF-002: CloudFront distributions require WAF protection.
 *
 * Scenarios covered:
 *   1. missing-web-acl-association — A CloudFront distribution is created
 *      without a WebACL associated (webAclId is undefined on the synthesized
 *      DistributionConfig), which is the exact condition the rule's
 *      hasWebAclAssociation() check looks for.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Origin bucket for the distribution (supporting resource).
    const originBucket = new s3.Bucket(this, 'OriginBucket');

    // Scenario: missing-web-acl-association
    // This Distribution is intentionally created without `webAclId`, so the
    // synthesized AWS::CloudFront::Distribution has no WebACLId on its
    // DistributionConfig — triggering the missing-web-acl-association finding.
    new cloudfront.Distribution(this, 'UnprotectedDistribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(originBucket),
      },
      defaultRootObject: 'index.html',
    });
  }
}
