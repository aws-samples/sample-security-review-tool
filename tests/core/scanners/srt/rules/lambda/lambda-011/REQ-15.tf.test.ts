import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (Terraform): A composite alarm in the plan combines underlying metric alarms
 * whose set of monitored alarms includes coverage of the assessed Lambda function,
 * even if no standalone metric alarm directly targets the function in isolation.
 *
 * Expected behavior: PASS - composite alarms aggregate the state of underlying metric
 * alarms; coverage via composite-alarm membership is acceptable.
 *
 * Note: In Terraform, an aws_cloudwatch_composite_alarm references underlying
 * aws_cloudwatch_metric_alarm resources via their ARNs (in alarm_rule). Those underlying
 * metric alarms are themselves resources in the plan. When the composite's underlying
 * metric alarms cover the assessed Lambda function, the function is effectively monitored.
 */
describe('LAMBDA-011 REQ-15 (TF): composite alarm aggregating coverage of the assessed function', () => {
  it('passes when a composite alarm aggregates underlying metric alarms that cover the assessed Lambda function', () => {
    const projectName = 'test-project';
    const functionName = 'assessed-fn';

    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.assessed',
      type: 'aws_lambda_function',
      name: 'assessed',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: functionName,
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::111111111111:role/lambda-role',
      },
    } as unknown as TerraformResource;

    // Underlying metric alarm covering the assessed function (Errors)
    const errorsAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        alarm_name: 'assessed-fn-errors',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: { FunctionName: functionName },
      },
    } as unknown as TerraformResource;

    // Underlying metric alarm covering the assessed function (Throttles)
    const throttlesAlarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.throttles',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'throttles',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        alarm_name: 'assessed-fn-throttles',
        namespace: 'AWS/Lambda',
        metric_name: 'Throttles',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: { FunctionName: functionName },
      },
    } as unknown as TerraformResource;

    // Composite alarm aggregating the underlying metric alarms above
    const compositeAlarm: TerraformResource = {
      address: 'aws_cloudwatch_composite_alarm.composite',
      type: 'aws_cloudwatch_composite_alarm',
      name: 'composite',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        alarm_name: 'assessed-fn-composite',
        alarm_rule:
          'ALARM("assessed-fn-errors") OR ALARM("assessed-fn-throttles")',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [
      lambdaResource,
      errorsAlarm,
      throttlesAlarm,
      compositeAlarm,
    ];

    const context: TfContext = {
      projectName,
      resource: lambdaResource,
      allResources,
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter as any, context);

    expect(result).toBeNull();
  });
});
