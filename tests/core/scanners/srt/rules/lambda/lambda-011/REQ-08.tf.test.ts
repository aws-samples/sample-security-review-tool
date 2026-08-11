import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 TF - REQ-08: Alarm targeting Lambda function with empty dimensions collection', () => {
  it('passes when alarm has empty dimensions object (account-wide coverage includes assessed function)', () => {
    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.assessed',
      type: 'aws_lambda_function',
      name: 'assessed',
      mode: 'managed',
      values: {
        function_name: 'my-assessed-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as TerraformResource;

    const alarmResource: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.empty_dims',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'empty_dims',
      mode: 'managed',
      values: {
        alarm_name: 'lambda-errors-aggregate',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: {},
      },
    } as TerraformResource;

    const allResources: TerraformResource[] = [lambdaResource, alarmResource];

    const factory = new Lambda011TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
