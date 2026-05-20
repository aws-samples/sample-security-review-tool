import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 CFN - REQ-10: Multiple alarms, at least one matches assessed function', () => {
  it('passes when one alarm targets the assessed Lambda among unrelated/different-function alarms', () => {
    const template: Template = {
      Resources: {
        AssessedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'assessed-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        OtherFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'other-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        // Alarm targeting a DIFFERENT Lambda function — should not satisfy coverage on its own
        AlarmForOtherFunction: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'other-fn-errors',
            Namespace: 'AWS/Lambda',
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [{ Name: 'FunctionName', Value: 'other-fn' }],
          },
        },
        // Unrelated alarm in a non-Lambda namespace — should be ignored entirely
        UnrelatedSqsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'sqs-queue-depth',
            Namespace: 'AWS/SQS',
            MetricName: 'ApproximateNumberOfMessagesVisible',
            Statistic: 'Average',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 100,
            ComparisonOperator: 'GreaterThanThreshold',
            Dimensions: [{ Name: 'QueueName', Value: 'some-queue' }],
          },
        },
        // Alarm correctly targeting the ASSESSED Lambda function — satisfies the requirement
        AlarmForAssessedFunction: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'assessed-fn-errors',
            Namespace: 'AWS/Lambda',
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [{ Name: 'FunctionName', Value: 'assessed-fn' }],
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.AssessedFunction,
      logicalId: 'AssessedFunction',
    };

    const factory = new Lambda011CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter as never, context);

    expect(result).toBeNull();
  });
});
