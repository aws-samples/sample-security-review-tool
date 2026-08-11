import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CloudFormation):
 * Scenario: An alarm's reference to the target Lambda function name depends on a value
 * that cannot be resolved at analysis time (e.g., Fn::ImportValue, Fn::GetAtt on another
 * resource, Fn::Sub with parameters, Ref to a CFN parameter).
 *
 * Expected Behavior: pass (no finding).
 *
 * Rationale: When the alarm's FunctionName dimension is computed from an unresolvable value,
 * the rule cannot conclusively determine that coverage is absent. To avoid false positives,
 * the rule should not flag the function when an alarm in the template might cover it.
 */
describe('LAMBDA-011 CFN - REQ-09: Alarm FunctionName dimension is unresolvable', () => {
  const factory = new Lambda011CfnAdapterFactory();

  function runControl(template: Template, logicalId: string) {
    const resource = template.Resources![logicalId];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };
    const adapter = factory.bind(context);
    return lambda011Control.run(adapter, context);
  }

  it('should pass when alarm FunctionName dimension uses Fn::ImportValue (unresolvable at analysis time)', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-known-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              {
                Name: 'FunctionName',
                Value: { 'Fn::ImportValue': 'SomeExportedFunctionName' },
              },
            ],
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });

  it('should pass when alarm FunctionName dimension uses Fn::GetAtt referencing another resource', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-known-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              {
                Name: 'FunctionName',
                Value: { 'Fn::GetAtt': ['SomeOtherResource', 'FunctionName'] },
              },
            ],
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });

  it('should pass when alarm FunctionName dimension uses Fn::Sub with a parameter (unresolvable)', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-known-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              {
                Name: 'FunctionName',
                Value: { 'Fn::Sub': '${EnvPrefix}-function' },
              },
            ],
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });

  it('should pass when alarm FunctionName dimension uses Ref to a CloudFormation parameter (unresolvable)', () => {
    const template: Template = {
      Parameters: {
        TargetFunctionNameParam: {
          Type: 'String',
        },
      },
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-known-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ErrorAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              {
                Name: 'FunctionName',
                Value: { Ref: 'TargetFunctionNameParam' },
              },
            ],
          },
        },
      },
    };

    const result = runControl(template, 'MyFunction');
    expect(result).toBeNull();
  });
});
