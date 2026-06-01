import { Stack, StackProps } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/**
 * LAMBDA-004 fixture: Lambda functions must have X-Ray active tracing enabled.
 *
 * Scenarios covered:
 * - missing-tracing-configuration: Lambda function created without setting
 *   `tracing: lambda.Tracing.ACTIVE`. CDK defaults to no TracingConfig in the
 *   synthesized template, which the adapter treats as missing tracing.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Scenario: missing-tracing-configuration
    // Lambda function with tracing left at default (PassThrough is not emitted
    // and ACTIVE is not set), so the synthesized AWS::Lambda::Function has no
    // TracingConfig.Mode === 'Active'.
    new lambda.Function(this, 'FunctionWithoutTracing', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
    });
  }
}
