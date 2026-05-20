import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-05 (Terraform): Alarm targets the assessed Lambda but has actions disabled', () => {
  it('flags the Lambda function when its CloudWatch alarm has actions_enabled set to false', () => {
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

    const alarmResource: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.my_function_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'my_function_errors',
      values: {
        alarm_name: 'my-function-errors',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        actions_enabled: false,
        dimensions: {
          FunctionName: 'my-function',
        },
      },
    } as TerraformResource;

    const allResources = [lambdaResource, alarmResource];

    const factory = new Lambda011TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('aws_lambda_function.my_function');
    expect(result?.status).toBe('Open');
  });
});
