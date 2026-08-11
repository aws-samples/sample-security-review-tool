import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 CFN - REQ-08: Alarm targeting Lambda function with empty dimensions collection', () => {
  it('passes when alarm has empty dimensions array (account-wide coverage includes assessed function)', () => {
    const template: Template = {
      Resources: {
        AssessedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-assessed-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        EmptyDimensionsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'lambda-errors-aggregate',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.AssessedFunction,
      logicalId: 'AssessedFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
