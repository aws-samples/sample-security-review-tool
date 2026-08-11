import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (Terraform): An alarm targets the assessed Lambda function on a Lambda
 * namespace metric that is NOT one of the commonly recommended reliability metrics
 * (Errors, Throttles, Duration, ConcurrentExecutions). Here the alarm monitors
 * `Invocations`. The rule's intent is to ensure monitoring coverage exists; any alarm
 * on the AWS/Lambda namespace targeting the function provides observability and
 * therefore satisfies the requirement.
 *
 * Expected behavior: PASS (no finding produced).
 */
describe('LAMBDA-011 (TF) REQ-12: alarm on a non-recommended Lambda metric still satisfies monitoring requirement', () => {
  it('produces no finding when an alarm targets the assessed function on the Invocations metric', () => {
    const assessedFunction: TerraformResource = {
      address: 'aws_lambda_function.assessed',
      type: 'aws_lambda_function',
      name: 'assessed',
      values: {
        function_name: 'my-assessed-function',
        handler: 'index.handler',
        runtime: 'nodejs20.x',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as unknown as TerraformResource;

    const invocationsAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.invocations',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'invocations',
      values: {
        alarm_name: 'my-assessed-function-invocations',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        // Not one of the commonly recommended reliability metrics:
        metric_name: 'Invocations',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1000,
        comparison_operator: 'GreaterThanThreshold',
        dimensions: {
          FunctionName: 'my-assessed-function',
        },
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [assessedFunction, invocationsAlarm];

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo(assessedFunction.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedFunction,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
