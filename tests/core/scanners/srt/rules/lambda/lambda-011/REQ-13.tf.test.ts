import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-011) — Terraform
 *
 * Scenario: An aws_cloudwatch_metric_alarm targets the assessed aws_lambda_function on
 * a Lambda metric, but the alarm has NO alarm actions configured (alarm_actions /
 * ok_actions / insufficient_data_actions are absent, and no notification target is
 * attached for any alarm state transition).
 *
 * Expected behavior: PASS (control returns null / no finding).
 *
 * Rationale: The rule validates the structural existence of monitoring coverage — not
 * the operational completeness of notification routing. An alarm without actions still
 * records state and history, which satisfies the IaC-level monitoring requirement.
 */
describe('LAMBDA-011 [TF] — alarm targeting the function with no alarm actions configured', () => {
  it('passes (no finding) when an alarm covers the Lambda but has no action targets', () => {
    const lambdaResource: TerraformResource = {
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

    const alarmWithoutActions: TerraformResource = {
      address: 'aws_cloudwatch_metric_alarm.errors_no_actions',
      type: 'aws_cloudwatch_metric_alarm',
      name: 'errors_no_actions',
      values: {
        // Lambda metric → alarm is in the Lambda namespace
        namespace: 'AWS/Lambda',
        metric_name: 'Errors',
        statistic: 'Sum',
        period: 60,
        evaluation_periods: 1,
        threshold: 1,
        comparison_operator: 'GreaterThanOrEqualToThreshold',
        // Targets the assessed function specifically.
        dimensions: {
          FunctionName: 'my-monitored-function',
        },
        // Intentionally NO alarm_actions, NO ok_actions, NO insufficient_data_actions.
        // actions_enabled is omitted (defaults to true), but there are no action targets.
      },
    } as unknown as TerraformResource;

    const allResources = [lambdaResource, alarmWithoutActions];

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo(lambdaResource.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    // Expected: PASS — the structural existence of the alarm satisfies the requirement,
    // even though no notification actions are wired up.
    expect(result).toBeNull();
  });
});
