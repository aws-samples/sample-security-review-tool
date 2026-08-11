import { describe, it, expect } from 'vitest';
import { Lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (CloudFormation):
 * When an AWS::CloudWatch::Alarm targets the assessed Lambda function by name but the
 * alarm Dimensions also include a Resource qualifier identifying a specific function
 * version or alias, the alarm only covers that version/alias's invocations. Invocations
 * against the unqualified function (or other versions/aliases) are not monitored, so the
 * function lacks complete coverage and the rule must FLAG the function.
 */
describe('LAMBDA-011 - REQ-11 (CFN): alarm scoped to a specific version/alias via Resource qualifier', () => {
  const stackName = 'test-stack';
  const lambdaLogicalId = 'MyFunction';
  const assessedFunctionName = 'my-function';

  function buildTemplate(alarmDimensions: Array<{ Name: string; Value: unknown }>): Template {
    return {
      Resources: {
        [lambdaLogicalId]: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: assessedFunctionName,
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorsAlarmForVersion: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'lambda-errors-version-1',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            ActionsEnabled: true,
            Dimensions: alarmDimensions,
          },
        },
      },
    } as unknown as Template;
  }

  function runControl(template: Template) {
    const control = new Lambda011Control();
    const factory = new Lambda011CfnAdapterFactory();
    const context: CfnContext = {
      stackName,
      template,
      resource: template.Resources![lambdaLogicalId],
      logicalId: lambdaLogicalId,
    };
    const adapter = factory.bind(context);
    return control.run(adapter as never, context);
  }

  it('flags the function when the alarm has a Resource dimension qualifying a specific published version', () => {
    const template = buildTemplate([
      { Name: 'FunctionName', Value: assessedFunctionName },
      { Name: 'Resource', Value: `${assessedFunctionName}:1` },
    ]);

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe(lambdaLogicalId);
  });

  it('flags the function when the alarm has a Resource dimension qualifying a specific alias', () => {
    const template = buildTemplate([
      { Name: 'FunctionName', Value: assessedFunctionName },
      { Name: 'Resource', Value: `${assessedFunctionName}:prod` },
    ]);

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe(lambdaLogicalId);
  });
});
