import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (LAMBDA-011) — CloudFormation
 *
 * AWS::Serverless::Function transforms into AWS::Lambda::Function and emits the same
 * AWS/Lambda metrics, so it carries the same monitoring requirement. Evaluating only
 * AWS::Lambda::Function left every SAM-defined function unassessed.
 */
describe('LAMBDA-011 [CFN] — REQ-17: AWS::Serverless::Function is assessed', () => {
  const factory = new Lambda011CfnAdapterFactory();

  const samFunction = {
    Type: 'AWS::Serverless::Function',
    Properties: {
      FunctionName: 'my-sam-function',
      Handler: 'index.handler',
      Runtime: 'python3.12',
      CodeUri: 's3://bucket/key',
    },
  };

  const evaluate = (resources: Record<string, unknown>, logicalId = 'MySamFunction') => {
    const template = { Resources: resources } as unknown as Template;
    const resource = template.Resources![logicalId];
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
    return lambda011Control.run(factory.bind(context), context);
  };

  it('applies to AWS::Serverless::Function', () => {
    expect(factory.appliesTo('AWS::Serverless::Function')).toBe(true);
  });

  it('flags a SAM function with no alarms anywhere in the template', () => {
    expect(evaluate({ MySamFunction: samFunction })?.check_id).toBe('LAMBDA-011');
  });

  it('flags a SAM function whose alarm has no actions configured', () => {
    const result = evaluate({
      MySamFunction: samFunction,
      ErrorsAlarm: {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          Namespace: 'AWS/Lambda',
          MetricName: 'Errors',
          Dimensions: [{ Name: 'FunctionName', Value: 'my-sam-function' }],
          Threshold: 1,
          EvaluationPeriods: 1,
          ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        },
      },
    });

    expect(result?.check_id).toBe('LAMBDA-011');
  });

  it('does NOT flag a SAM function covered by an alarm with an action', () => {
    const result = evaluate({
      MySamFunction: samFunction,
      ErrorsAlarm: {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          Namespace: 'AWS/Lambda',
          MetricName: 'Errors',
          AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
          Dimensions: [{ Name: 'FunctionName', Value: 'my-sam-function' }],
          Threshold: 1,
          EvaluationPeriods: 1,
          ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        },
      },
    });

    expect(result).toBeNull();
  });

  it('resolves a Ref to the assessed SAM function in the alarm dimension', () => {
    const result = evaluate({
      MySamFunction: samFunction,
      ErrorsAlarm: {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          Namespace: 'AWS/Lambda',
          MetricName: 'Errors',
          AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
          Dimensions: [{ Name: 'FunctionName', Value: { Ref: 'MySamFunction' } }],
          Threshold: 1,
          EvaluationPeriods: 1,
          ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        },
      },
    });

    expect(result).toBeNull();
  });

  it('does not credit a SAM function with an alarm that targets a different function', () => {
    const result = evaluate({
      MySamFunction: samFunction,
      OtherSamFunction: { ...samFunction, Properties: { ...samFunction.Properties, FunctionName: 'other-function' } },
      ErrorsAlarm: {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          Namespace: 'AWS/Lambda',
          MetricName: 'Errors',
          AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
          Dimensions: [{ Name: 'FunctionName', Value: { Ref: 'OtherSamFunction' } }],
          Threshold: 1,
          EvaluationPeriods: 1,
          ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        },
      },
    });

    expect(result?.check_id).toBe('LAMBDA-011');
  });
});
