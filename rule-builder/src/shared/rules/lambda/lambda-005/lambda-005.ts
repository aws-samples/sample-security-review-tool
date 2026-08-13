import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';

/**
 * Fixture for LAMBDA-005.
 *
 * Scenario 1: wildcard-action-and-resource
 *   A Lambda execution role has an inline policy statement granting
 *   Action: "*" on Resource: "*".
 *
 * Scenario 2: overly-broad-managed-policy
 *   A separate Lambda execution role has the AWS managed
 *   "AdministratorAccess" policy attached.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // ---- Scenario 1: wildcard-action-and-resource ----
    const wildcardRole = new iam.Role(this, 'WildcardGrantExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });

    wildcardRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'WildcardGrant',
        actions: ['*'],
        resources: ['*'],
      }),
    );

    new lambda.CfnFunction(this, 'WildcardGrantFunction', {
      functionName: 'wildcard-grant-function',
      runtime: 'nodejs18.x',
      handler: 'index.handler',
      role: wildcardRole.roleArn,
      code: {
        zipFile: 'exports.handler = async () => {};',
      },
    });

    // ---- Scenario 2: overly-broad-managed-policy ----
    const broadPolicyRole = new iam.Role(this, 'BroadManagedPolicyExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });

    broadPolicyRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess'),
    );

    new lambda.CfnFunction(this, 'BroadManagedPolicyFunction', {
      functionName: 'broad-managed-policy-function',
      runtime: 'nodejs18.x',
      handler: 'index.handler',
      role: broadPolicyRole.roleArn,
      code: {
        zipFile: 'exports.handler = async () => {};',
      },
    });
  }
}
