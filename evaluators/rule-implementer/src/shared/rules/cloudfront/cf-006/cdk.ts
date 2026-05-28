import { Stack, StackProps } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

/**
 * CF-006: CloudFront distributions must enable origin access control.
 *
 * The control's evaluate() returns on the first matching scenario per
 * resource (S3-origin scenario is checked before non-S3 OAC-eligible).
 * To trigger both scenarios, we use two separate CloudFront distributions:
 *
 *   - Distribution A: an S3 bucket origin without OAC and without legacy OAI
 *     -> triggers `s3-origin-without-access-control`
 *   - Distribution B: a Lambda Function URL origin (OAC-eligible non-S3)
 *     without OAC -> triggers
 *     `non-s3-oac-eligible-origin-without-access-control`.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // -----------------------------------------------------------------
    // Scenario 1: S3 origin without origin access control / OAI
    // -----------------------------------------------------------------
    // `S3BucketOrigin.withBucketDefaults` produces an S3 origin with no
    // OAC and no legacy OAI, which is exactly what the rule looks for.
    const assetBucket = new s3.Bucket(this, 'UnprotectedAssetsBucket');

    new cloudfront.Distribution(this, 'S3OriginUnprotectedDistribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withBucketDefaults(assetBucket),
      },
    });

    // -----------------------------------------------------------------
    // Scenario 2: Non-S3 OAC-eligible origin without origin access control
    // -----------------------------------------------------------------
    // A Lambda Function URL origin matches the OAC-eligible non-S3 domain
    // pattern (`*.lambda-url.<region>.on.aws`). Using `FunctionUrlOrigin`
    // without an OAC leaves `OriginAccessControlId` unset on the origin.
    const fn = new lambda.Function(this, 'EdgeFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(
        "exports.handler = async () => ({ statusCode: 200, body: 'ok' });",
      ),
    });
    const fnUrl = fn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    new cloudfront.Distribution(this, 'LambdaUrlOriginUnprotectedDistribution', {
      defaultBehavior: {
        origin: new origins.FunctionUrlOrigin(fnUrl),
      },
    });
  }
}
