import { describe, it, expect } from 'vitest';
import { Lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-03 (Terraform): Alarm exists but uses non-Lambda metric namespace', () => {
  it('should flag a Lambda function when the only alarm uses a metric namespace unrelated to Lambda', () => {
    const lambdaResource: any = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    };

    const unrelatedAlarmResource: any = {
      address: 'aws_cloudwatch_metric_alarm.unrelated',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'unrelated',
      values: {
        alarm_name: 'unrelated-alarm',
        // Namespace is NOT AWS/Lambda - this alarm cannot be monitoring a Lambda function
        namespace: 'AWS/EC2',
        metric_name: 'CPUUtilization',
        statistic: 'Average',
        period: 300,
        evaluation_periods: 1,
        threshold: 80,
        comparison_operator: 'GreaterThanThreshold',
        dimensions: {
          InstanceId: 'i-0123456789abcdef0',
        },
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource, unrelatedAlarmResource],
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const control = new Lambda011Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('aws_lambda_function.my_function');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.status).toBe('Open');
  });
});
