import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (Terraform): An alarm targets the assessed Lambda function on a Lambda
 * metric, but the threshold, statistic, or comparison operator are tuned in a way
 * that would be very unlikely to trigger in practice. The rule only verifies the
 * structural existence of an alarm covering the function; threshold appropriateness
 * is out of scope, so the control must PASS.
 */
describe('LAMBDA-011 REQ-14 (Terraform): alarm with impractical threshold/statistic/comparison still passes', () => {
  const buildContext = (resources: TerraformResource[], assessedAddress: string): TfContext => ({
    projectName: 'test-project',
    resource: resources.find(r => r.address === assessedAddress)!,
    allResources: resources,
  });

  it('passes when alarm has an absurdly high threshold that would never trigger', () => {
    const lambda: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
      },
    } as TerraformResource;

    const alarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.my_alarm',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'my_alarm',
      values: {
        alarm_name: 'my-function-errors',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        // Impractical threshold - would essentially never trigger
        threshold: 1_000_000_000,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        actions_enabled: true,
        dimensions: {
          FunctionName: 'my-function',
        },
      },
    } as TerraformResource;

    const factory = new Lambda011TfAdapterFactory();
    const context = buildContext([lambda, alarm], lambda.address);
    const adapter = factory.bind(context);

    const result = lambda011Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when alarm uses an unlikely statistic/comparison operator combination', () => {
    const lambda: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
      },
    } as TerraformResource;

    const alarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.my_alarm',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'my_alarm',
      values: {
        alarm_name: 'my-function-errors-min',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        // Minimum of error counts is essentially always 0 -> alarm
        // with LessThanThreshold below 0 would never fire in practice.
        statistic: 'Minimum',
        period: 60,
        evaluation_periods: 1,
        threshold: -1,
        comparison_operator: 'LessThanThreshold',
        actions_enabled: true,
        dimensions: {
          FunctionName: 'my-function',
        },
      },
    } as TerraformResource;

    const factory = new Lambda011TfAdapterFactory();
    const context = buildContext([lambda, alarm], lambda.address);
    const adapter = factory.bind(context);

    const result = lambda011Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
