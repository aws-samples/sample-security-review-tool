import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-06 (Terraform)', () => {
  it('flags an assessed Lambda function that lacks alarm coverage even when other Lambda functions in the project are covered', () => {
    const coveredFunction: TerraformResource = {
      address: 'aws_lambda_function.covered',
      type: 'aws_lambda_function',
      name: 'covered',
      values: {
        function_name: 'covered-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as never;

    const uncoveredFunction: TerraformResource = {
      address: 'aws_lambda_function.uncovered',
      type: 'aws_lambda_function',
      name: 'uncovered',
      values: {
        function_name: 'uncovered-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as never;

    const coveredAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.covered_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'covered_errors',
      values: {
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        actions_enabled: true,
        dimensions: {
          FunctionName: 'covered-function',
        },
      },
    } as never;

    const allResources = [coveredFunction, uncoveredFunction, coveredAlarm];

    const factory = new Lambda011TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: uncoveredFunction,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('aws_lambda_function.uncovered');
    expect(result?.status).toBe('Open');
  });
});
