import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (CloudFormation): An alarm targets the assessed Lambda function on a Lambda
 * metric, but the threshold, statistic, or comparison operator are tuned in a way
 * that would be very unlikely to trigger in practice. The rule only verifies the
 * structural existence of an alarm covering the function; threshold appropriateness
 * is out of scope, so the control must PASS.
 */
describe('LAMBDA-011 REQ-14 (CloudFormation): alarm with impractical threshold/statistic/comparison still passes', () => {
  const buildContext = (template: Template, logicalId: string): CfnContext => ({
    stackName: 'test-stack',
    template,
    resource: template.Resources![logicalId],
    logicalId,
  });

  it('passes when alarm has an absurdly high threshold that would never trigger', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        MyAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'my-function-errors',
            Namespace: 'AWS/Lambda',
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            // Impractical threshold - would essentially never trigger
            Threshold: 1_000_000_000,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: 'my-function' },
            ],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const context = buildContext(template, 'MyFunction');
    const adapter = factory.bind(context);

    const result = lambda011Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when alarm uses an unlikely statistic/comparison operator combination', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        MyAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'my-function-errors-min',
            Namespace: 'AWS/Lambda',
            MetricName: 'Errors',
            // Minimum of error counts is essentially always 0 -> alarm
            // with LessThanThreshold below 0 would never fire in practice.
            Statistic: 'Minimum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: -1,
            ComparisonOperator: 'LessThanThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: 'my-function' },
            ],
          },
        },
      },
    };

    const factory = new Lambda011CfnAdapterFactory();
    const context = buildContext(template, 'MyFunction');
    const adapter = factory.bind(context);

    const result = lambda011Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
