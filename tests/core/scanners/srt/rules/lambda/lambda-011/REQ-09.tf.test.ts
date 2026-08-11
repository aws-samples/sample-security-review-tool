import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (Terraform):
 * Scenario: An alarm's reference to the target Lambda function name depends on a value
 * that cannot be resolved at analysis time. In Terraform plan output, an unknown value
 * (e.g., a value computed from another resource not yet created, or referenced via a
 * variable that wasn't fully resolved) is typically represented as `null` or absent in
 * `values`, and tracked separately in `after_unknown`. From the rule's perspective the
 * `dimensions.FunctionName` is non-string / unresolvable.
 *
 * Expected Behavior: pass (no finding).
 *
 * Rationale: When the alarm's FunctionName dimension is computed from an unresolvable value,
 * the rule cannot conclusively determine that coverage is absent. To avoid false positives,
 * the rule should not flag the function when an alarm in the template might cover it.
 */
describe('LAMBDA-011 TF - REQ-09: Alarm FunctionName dimension is unresolvable', () => {
  const factory = new Lambda011TfAdapterFactory();

  function runControl(allResources: TerraformResource[], targetAddress: string) {
    const resource = allResources.find(r => r.address === targetAddress)!;
    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources,
    };
    const adapter = factory.bind(context);
    return lambda011Control.run(adapter, context);
  }

  it('should pass when alarm dimensions.FunctionName is unresolvable (null - unknown at plan time)', () => {
    const lambdaFn: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        function_name: 'my-known-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as unknown as TerraformResource;

    const alarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors',
      values: {
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        // FunctionName is present as a key, but its value is unresolvable (null/unknown at plan time)
        dimensions: {
          FunctionName: null,
        },
      },
    } as unknown as TerraformResource;

    const result = runControl([lambdaFn, alarm], 'aws_lambda_function.my_fn');
    expect(result).toBeNull();
  });

  it('should pass when alarm dimensions.FunctionName is unresolvable (undefined - unknown at plan time)', () => {
    const lambdaFn: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        function_name: 'my-known-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as unknown as TerraformResource;

    const alarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors',
      values: {
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        // FunctionName key present but value undefined - unresolvable
        dimensions: {
          FunctionName: undefined,
        },
      },
    } as unknown as TerraformResource;

    const result = runControl([lambdaFn, alarm], 'aws_lambda_function.my_fn');
    expect(result).toBeNull();
  });

  it('should pass when assessed Lambda function_name itself is unresolvable but alarm has a FunctionName dimension', () => {
    const lambdaFn: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        // function_name unresolvable at plan time
        function_name: null,
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as unknown as TerraformResource;

    const alarm: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors',
      values: {
        namespace: 'AWS/Lambda',
        alarm_actions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: {
          FunctionName: 'some-resolved-name',
        },
      },
    } as unknown as TerraformResource;

    const result = runControl([lambdaFn, alarm], 'aws_lambda_function.my_fn');
    expect(result).toBeNull();
  });
});
