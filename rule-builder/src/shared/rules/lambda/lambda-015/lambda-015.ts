import { Stack, StackProps } from 'aws-cdk-lib';
import { CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { Role, ServicePrincipal, ManagedPolicy } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

/**
 * Fixture for LAMBDA-015: Lambda container images must use a specific version
 * tag instead of `latest`.
 *
 * The control's evaluate() flags a Lambda function whose container ImageUri
 * either:
 *   1. Uses an explicit `:latest` tag, OR
 *   2. Has neither a tag nor a digest (resolves to `latest` at pull time).
 *
 * Both code paths emit a finding under the single `use-specific-version-tag`
 * scenario. We trigger each path with a separate Lambda function.
 *
 * Image URIs MUST be statically resolvable literal strings. CDK's L2
 * `DockerImageCode.fromEcr()` synthesizes an Fn::Join over Fn::GetAtt of the
 * repository's repositoryUri attribute, which preprocessing leaves opaque, so
 * the rule would never see the value. Using CfnFunction with a literal
 * Code.ImageUri ensures the rule sees the exact string we intend.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const role = new Role(this, 'LambdaExecutionRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Scenario: use-specific-version-tag (path 1: explicit `:latest` tag).
    new CfnFunction(this, 'FunctionWithLatestTag', {
      packageType: 'Image',
      role: role.roleArn,
      code: {
        imageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-lambda-app:latest',
      },
    });

    // Scenario: use-specific-version-tag (path 2: no tag and no digest;
    // resolves to `latest` at pull time).
    new CfnFunction(this, 'FunctionWithoutTagOrDigest', {
      packageType: 'Image',
      role: role.roleArn,
      code: {
        imageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-lambda-app',
      },
    });
  }
}
