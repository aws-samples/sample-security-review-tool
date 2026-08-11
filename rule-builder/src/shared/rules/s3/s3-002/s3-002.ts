import { Stack, StackProps } from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Fixture for S3-002: "S3 bucket policies must not grant access to untrusted principals"
 *
 * Triggers both remediation scenarios:
 *  1. wildcard-principal-without-condition
 *     - An Allow statement granting access to a wildcard principal ("*" / {"AWS": "*"})
 *       with no Condition constraining who may assume it.
 *  2. service-principal-without-source-scope
 *     - An Allow statement granting access to an AWS service principal with no
 *       Condition scoping the source account / source ARN / source owner.
 *
 * The control's evaluate() method returns on the FIRST matching finding per
 * resource (i.e. per bucket policy), checking the wildcard-principal scenario
 * before the service-principal scenario. To exercise both scenarios, each is
 * placed on its own bucket policy so the statements don't shadow one another.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // --- Scenario 1: wildcard-principal-without-condition ---
    const wildcardPrincipalBucket = new s3.Bucket(this, 'WildcardPrincipalBucket', {
      bucketName: 'fixture-s3-002-wildcard-principal',
    });

    wildcardPrincipalBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowWildcardPrincipalNoCondition',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: ['s3:GetObject'],
        resources: [wildcardPrincipalBucket.arnForObjects('*')],
        // Intentionally no condition — this is what triggers the scenario.
      }),
    );

    // --- Scenario 2: service-principal-without-source-scope ---
    const servicePrincipalBucket = new s3.Bucket(this, 'ServicePrincipalBucket', {
      bucketName: 'fixture-s3-002-service-principal',
    });

    servicePrincipalBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowServicePrincipalNoSourceScope',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudfront.amazonaws.com')],
        actions: ['s3:GetObject'],
        resources: [servicePrincipalBucket.arnForObjects('*')],
        // Intentionally no aws:SourceAccount / aws:SourceArn / aws:SourceOwner
        // condition — this is what triggers the scenario.
      }),
    );
  }
}
