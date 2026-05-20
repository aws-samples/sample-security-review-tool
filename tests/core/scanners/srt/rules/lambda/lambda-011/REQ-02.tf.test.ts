import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-02 (Terraform): Lambda with monitoring CloudWatch alarm should pass', () => {
  it('should pass when an aws_cloudwatch_metric_alarm in the plan monitors the Lambda function via AWS/Lambda namespace and FunctionName dimension', () => {
    const functionName = 'my-lambda-function';

    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.my_lambda',
      type: 'aws_lambda_function',
      name: 'my_lambda',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: functionName,
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as unknown as TerraformResource;

    const alarmResource: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.my_lambda_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'my_lambda_errors',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        alarm_name: 'my-lambda-errors-alarm',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        dimensions: {
          FunctionName: functionName,
        },
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [lambdaResource, alarmResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
