import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-06 (CloudFormation)', () => {
  it('flags an assessed Lambda function that lacks alarm coverage even when other Lambda functions in the template are covered', () => {
    const template = {
      Resources: {
        CoveredFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'covered-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
        UncoveredFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'uncovered-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
        CoveredFunctionErrorsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            ActionsEnabled: true,
            Dimensions: [
              { Name: 'FunctionName', Value: { Ref: 'CoveredFunction' } },
            ],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template: template as never,
      resource: template.Resources.UncoveredFunction as never,
      logicalId: 'UncoveredFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('UncoveredFunction');
    expect(result?.status).toBe('Open');
  });
});
