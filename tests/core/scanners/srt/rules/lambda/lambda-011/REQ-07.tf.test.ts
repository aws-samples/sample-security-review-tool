import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-07 (Terraform): Alarm with Lambda namespace but no dimensions', () => {
  it('passes when an AWS/Lambda alarm exists without dimensions (account-wide coverage)', () => {
    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as TerraformResource;

    const accountWideAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.account_wide_lambda_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'account_wide_lambda_errors',
      values: {
        alarm_name: 'account-wide-lambda-errors',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        // dimensions intentionally omitted: aggregates across all Lambda functions
      },
    } as TerraformResource;

    const allResources = [lambdaResource, accountWideAlarm];

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    // Expected behavior: pass (no finding) because the namespace-wide alarm
    // covers the assessed function via account-wide aggregation.
    expect(result).toBeNull();
  });
});
