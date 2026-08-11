import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-011) — Terraform
 *
 * Scenario: An aws_cloudwatch_metric_alarm targets the assessed aws_lambda_function on a
 * Lambda metric, but the alarm has NO alarm actions configured.
 *
 * Expected behavior: FLAG.
 *
 * An alarm with no actions notifies nobody when it breaches, so it is not monitoring
 * coverage. AWS treats it as non-compliant via the managed Config rule
 * cloudwatch-alarm-action-check. This is REQ-05's defect reached another way — actions
 * present but disabled there, no actions at all here — so the verdict matches.
 */
describe('LAMBDA-011 [TF] — REQ-13: alarm targeting the function with no alarm actions', () => {
  const factory = new Lambda011TfAdapterFactory();

  const lambdaResource = {
    address: 'aws_lambda_function.assessed',
    type: 'aws_lambda_function',
    name: 'assessed',
    values: {
      function_name: 'my-monitored-function',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/lambda-role',
    },
  } as unknown as TerraformResource;

  const evaluate = (alarmValues: Record<string, unknown>) => {
    const alarmResource = {
      address: 'aws_cloudwatch_metric_alarm.errors',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors',
      values: {
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        dimensions: { FunctionName: 'my-monitored-function' },
        ...alarmValues,
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource, alarmResource],
    };

    return lambda011Control.run(factory.bind(context), context);
  };

  it('flags when the alarm has no alarm_actions at all', () => {
    expect(evaluate({})?.check_id).toBe('LAMBDA-011');
  });

  it('flags when alarm_actions is present but empty', () => {
    expect(evaluate({ alarm_actions: [] })?.check_id).toBe('LAMBDA-011');
  });

  it('flags when only ok_actions is configured, since no alarm-state action exists', () => {
    expect(evaluate({ ok_actions: ['arn:aws:sns:us-east-1:123456789012:recovered'] })?.check_id).toBe('LAMBDA-011');
  });

  it('does NOT flag once an alarm_actions target is configured (REQ-16)', () => {
    expect(evaluate({ alarm_actions: ['arn:aws:sns:us-east-1:123456789012:alerts'] })).toBeNull();
  });
});
