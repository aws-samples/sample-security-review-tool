import { describe, it, expect } from 'vitest';
import { Lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (Terraform):
 * When an aws_cloudwatch_metric_alarm targets the assessed aws_lambda_function by name
 * but its dimensions map also includes a Resource qualifier identifying a specific
 * function version or alias, the alarm only covers that version/alias's invocations.
 * Invocations against the unqualified function (or other versions/aliases) are not
 * monitored, so the function lacks complete coverage and the rule must FLAG it.
 */
describe('LAMBDA-011 - REQ-11 (TF): alarm scoped to a specific version/alias via Resource qualifier', () => {
  const projectName = 'test-project';
  const assessedFunctionName = 'my-function';

  const lambdaResource: TerraformResource = {
    address: 'aws_lambda_function.my_function',
    type: 'aws_lambda_function',
    name: 'my_function',
    mode: 'managed',
    provider_name: 'registry.terraform.io/hashicorp/aws',
    schema_version: 0,
    values: {
      function_name: assessedFunctionName,
      runtime: 'nodejs18.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
    },
  } as unknown as TerraformResource;

  function buildAlarm(dimensions: Record<string, string>): TerraformResource {
    return {
      address: 'aws_cloudwatch_metric_alarm.errors_version',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors_version',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      schema_version: 0,
      values: {
        alarm_name: 'lambda-errors-version-1',
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        actions_enabled: true,
        dimensions,
      },
    } as unknown as TerraformResource;
  }

  function runControl(allResources: TerraformResource[]) {
    const control = new Lambda011Control();
    const factory = new Lambda011TfAdapterFactory();
    const context: TfContext = {
      projectName,
      resource: lambdaResource,
      allResources,
    };
    const adapter = factory.bind(context);
    return control.run(adapter as never, context);
  }

  it('flags the function when the alarm has a Resource dimension qualifying a specific published version', () => {
    const alarm = buildAlarm({
      FunctionName: assessedFunctionName,
      Resource: `${assessedFunctionName}:1`,
    });

    const result = runControl([lambdaResource, alarm]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceType).toBe('aws_lambda_function');
  });

  it('flags the function when the alarm has a Resource dimension qualifying a specific alias', () => {
    const alarm = buildAlarm({
      FunctionName: assessedFunctionName,
      Resource: `${assessedFunctionName}:prod`,
    });

    const result = runControl([lambdaResource, alarm]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceType).toBe('aws_lambda_function');
  });
});
