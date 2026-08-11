import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-05 (CloudFormation): Alarm targets the assessed Lambda but has actions disabled', () => {
  it('flags the Lambda function when its CloudWatch alarm has ActionsEnabled set to false', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        MyFunctionErrorsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'my-function-errors',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            ActionsEnabled: false,
            Dimensions: [
              { Name: 'FunctionName', Value: { Ref: 'MyFunction' } },
            ],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyFunction,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('MyFunction');
    expect(result?.status).toBe('Open');
  });
});
