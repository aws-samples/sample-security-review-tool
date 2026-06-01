import { Stack, StackProps } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

/**
 * Fixture for LAMBDA-011: Lambda functions must have CloudWatch alarms for monitoring.
 *
 * Remediation scenarios:
 *  - missing-monitoring-alarm: a Lambda function exists with no qualifying CloudWatch
 *    alarm (AWS/Lambda namespace, ActionsEnabled !== false, covering this function or
 *    account-wide, and not scoped to a specific version/alias).
 *
 * To trigger the only scenario, we define a Lambda function and intentionally do NOT
 * create any CloudWatch alarms for it.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Non-compliant: Lambda function with no CloudWatch alarms configured.
    new lambda.Function(this, 'UnmonitoredFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(
        'exports.handler = async () => ({ statusCode: 200, body: "ok" });',
      ),
    });
  }
}
