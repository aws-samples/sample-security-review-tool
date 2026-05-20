import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-04 (Terraform): Alarm referencing a different Lambda function should be flagged', () => {
  it('flags the assessed Lambda function when the only AWS/Lambda alarm targets a different function via its FunctionName dimension', () => {
    const assessedFunction: TerraformResource = {
      address: 'aws_lambda_function.assessed',
      type: 'aws_lambda_function',
      name: 'assessed',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'assessed-function',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as unknown as TerraformResource;

    const otherFunction: TerraformResource = {
      address: 'aws_lambda_function.other',
      type: 'aws_lambda_function',
      name: 'other',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'other-function',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as unknown as TerraformResource;

    // Alarm in the AWS/Lambda namespace, but its FunctionName dimension points
    // to "other-function" — i.e. NOT the function being assessed.
    const alarmForOther: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.other_errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'other_errors',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        alarm_name: 'OtherFunctionErrors',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: {
          FunctionName: 'other-function',
        },
      },
    } as unknown as TerraformResource;

    const allResources = [assessedFunction, otherFunction, alarmForOther];

    const factory = new Lambda011TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedFunction,
      allResources,
    };

    expect(factory.appliesTo(assessedFunction.type)).toBe(true);
    const adapter = factory.bind(context);

    // The only Lambda-namespace alarm is for a different function, so the
    // assessed function lacks monitoring coverage and must be flagged.
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('aws_lambda_function.assessed');
    expect(result?.status).toBe('Open');
  });
});
