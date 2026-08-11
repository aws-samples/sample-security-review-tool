import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-04 (CloudFormation): Alarm referencing a different Lambda function should be flagged', () => {
  it('flags the assessed Lambda function when the only AWS/Lambda alarm targets a different function via its function-name dimension', () => {
    const template: Template = {
      Resources: {
        AssessedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'assessed-function',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        OtherFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'other-function',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        // Alarm uses the Lambda namespace but is scoped to OtherFunction via FunctionName dimension.
        AlarmForOtherFunction: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'OtherFunctionErrors',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: 'other-function' },
            ],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const assessedResource = template.Resources!.AssessedFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: assessedResource,
      logicalId: 'AssessedFunction',
    };

    expect(factory.appliesTo(assessedResource.Type)).toBe(true);
    const adapter = factory.bind(context);

    // The alarm in the template targets a different function, so the assessed
    // function has no monitoring coverage and the control must produce a finding.
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('AssessedFunction');
    expect(result?.status).toBe('Open');
  });
});
