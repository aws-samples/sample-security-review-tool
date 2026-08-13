import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';

/**
 * Fixture for ATH-002: Athena WorkGroups must use an S3 output location bucket
 * whose bucket policy includes a Deny statement enforcing HTTPS/TLS
 * (aws:SecureTransport) for all requests.
 *
 * Triggers both remediation scenarios:
 *  1. missing-output-location: a workgroup with no ResultConfiguration.OutputLocation.
 *  2. output-bucket-allows-insecure-transport: a workgroup whose OutputLocation
 *     points at an S3 bucket that has a bucket policy, but that policy does not
 *     deny non-TLS requests.
 */
export class FixtureStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Scenario 1: MISSING_OUTPUT_LOCATION
    // No ResultConfiguration.OutputLocation is provided, and the workgroup does not
    // use managed query results storage, so the adapter reports a missing output location.
    new athena.CfnWorkGroup(this, 'WorkGroupMissingOutputLocation', {
      name: 'missing-output-location-wg',
      workGroupConfiguration: {
        resultConfiguration: {},
      },
    });

    // Scenario 2: OUTPUT_BUCKET_ALLOWS_INSECURE_TRANSPORT
    // The output bucket exists in the template and has a bucket policy attached,
    // but that policy does not include a Deny statement enforcing aws:SecureTransport.
    const insecureBucket = new s3.Bucket(this, 'InsecureOutputBucket', {
      bucketName: 'ath002-insecure-output-bucket',
    });

    insecureBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:GetObject'],
        resources: [insecureBucket.arnForObjects('*')],
      }),
    );

    new athena.CfnWorkGroup(this, 'WorkGroupInsecureOutputBucket', {
      name: 'insecure-output-bucket-wg',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: 's3://ath002-insecure-output-bucket/results/',
        },
      },
    });
  }
}
