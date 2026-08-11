import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-02 (CloudFormation): Lambda with monitoring CloudWatch alarm should pass', () => {
  it('should pass when a CloudWatch alarm in the template monitors the Lambda function via AWS/Lambda namespace and FunctionName dimension', () => {
    const functionLogicalId = 'MyLambdaFunction';
    const functionName = 'my-lambda-function';

    const template: Template = {
      Resources: {
        [functionLogicalId]: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: functionName,
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        MyLambdaErrorsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'my-lambda-errors-alarm',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Dimensions: [
              {
                Name: 'FunctionName',
                Value: functionName,
              },
            ],
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources![functionLogicalId],
      logicalId: functionLogicalId,
    };

    const factory = new Lambda011CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
