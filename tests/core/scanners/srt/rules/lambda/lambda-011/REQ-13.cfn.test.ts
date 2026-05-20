import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-011) — CloudFormation
 *
 * Scenario: A CloudWatch alarm targets the assessed Lambda function on a Lambda metric,
 * but the alarm has NO alarm actions configured (no AlarmActions / OKActions /
 * InsufficientDataActions and no notification target attached for any state transition).
 *
 * Expected behavior: PASS (control returns null / no finding).
 *
 * Rationale: The rule validates the structural existence of monitoring coverage — not
 * the operational completeness of notification routing. An alarm without actions still
 * records state and history, which satisfies the IaC-level monitoring requirement.
 */
describe('LAMBDA-011 [CFN] — alarm targeting the function with no alarm actions configured', () => {
  it('passes (no finding) when an alarm covers the Lambda but has no action targets', () => {
    const template = {
      Resources: {
        AssessedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-monitored-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorsAlarmWithoutActions: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            // Lambda metric → alarm is in the Lambda namespace
            Namespace: 'AWS/Lambda',
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            // Targets the assessed function specifically.
            Dimensions: [
              { Name: 'FunctionName', Value: 'my-monitored-function' },
            ],
            // Intentionally NO AlarmActions, NO OKActions, NO InsufficientDataActions.
            // ActionsEnabled is omitted (defaults to true), but there are no action targets.
          },
        },
      },
    } as const;

    const factory = new Lambda011CfnAdapterFactory();
    const logicalId = 'AssessedFunction';
    const resource = template.Resources[logicalId];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as unknown as CfnContext['template'],
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    // Expected: PASS — the structural existence of the alarm satisfies the requirement,
    // even though no notification actions are wired up.
    expect(result).toBeNull();
  });
});
