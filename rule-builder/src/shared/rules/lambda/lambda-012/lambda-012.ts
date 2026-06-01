import { Stack, StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/**
 * LAMBDA-012: Lambda functions must have unique IAM execution roles.
 *
 * Scenarios triggered:
 *  - shared-execution-role: Two Lambda functions share the same explicitly-provided
 *    IAM execution role, so the adapter detects that the role string referenced by
 *    one function is also referenced by another resource in the same template.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // A single execution role intended (incorrectly) to be reused across
    // multiple Lambda functions.
    const sharedExecutionRole = new iam.Role(this, 'SharedLambdaExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // First Lambda function using the shared role.
    new lambda.Function(this, 'FunctionA', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      role: sharedExecutionRole,
    });

    // Second Lambda function using the same shared role -- this is the
    // non-compliant configuration that LAMBDA-012 detects.
    new lambda.Function(this, 'FunctionB', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      role: sharedExecutionRole,
    });
  }
}
