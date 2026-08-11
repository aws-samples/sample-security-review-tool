import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 TF - REQ-10: Multiple alarms, at least one matches assessed function', () => {
  it('passes when one alarm targets the assessed Lambda among unrelated/different-function alarms', () => {
    const assessedFunction: TerraformResource = {
      address: 'aws_lambda_function.assessed',
      type: 'aws_lambda_function',
      name: 'assessed',
      values: {
        function_name: 'assessed-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as TerraformResource;

    const otherFunction: TerraformResource = {
      address: 'aws_lambda_function.other',
      type: 'aws_lambda_function',
      name: 'other',
      values: {
        function_name: 'other-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as TerraformResource;

    // Alarm targeting a DIFFERENT Lambda function
    const alarmForOtherFunction: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.other_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'other_errors',
      values: {
        alarm_name: 'other-fn-errors',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: { FunctionName: 'other-fn' },
      },
    } as TerraformResource;

    // Unrelated alarm in a non-Lambda namespace
    const unrelatedSqsAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.sqs_depth',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'sqs_depth',
      values: {
        alarm_name: 'sqs-queue-depth',
        namespace: 'AWS/SQS',
        metric_name: 'ApproximateNumberOfMessagesVisible',
        statistic: 'Average',
        period: 60,
        evaluation_periods: 1,
        threshold: 100,
        comparison_operator: 'GreaterThanThreshold',
        dimensions: { QueueName: 'some-queue' },
      },
    } as TerraformResource;

    // Alarm correctly targeting the ASSESSED Lambda function
    const alarmForAssessedFunction: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.assessed_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'assessed_errors',
      values: {
        alarm_name: 'assessed-fn-errors',
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: { FunctionName: 'assessed-fn' },
      },
    } as TerraformResource;

    const allResources: TerraformResource[] = [
      assessedFunction,
      otherFunction,
      alarmForOtherFunction,
      unrelatedSqsAlarm,
      alarmForAssessedFunction,
    ];

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedFunction,
      allResources,
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter as never, context);

    expect(result).toBeNull();
  });
});
