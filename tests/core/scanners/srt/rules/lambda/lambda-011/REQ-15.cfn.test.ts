import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (CloudFormation): A composite alarm in the template combines underlying metric
 * alarms whose set of monitored alarms includes coverage of the assessed Lambda function,
 * even if no standalone metric alarm directly targets the function in isolation.
 *
 * Expected behavior: PASS - composite alarms aggregate the state of underlying metric
 * alarms; coverage via composite-alarm membership is acceptable.
 *
 * Note: In CloudFormation, an AWS::CloudWatch::CompositeAlarm references underlying
 * AWS::CloudWatch::Alarm resources via their ARNs (in AlarmRule). Those underlying
 * metric alarms are themselves resources in the template. When the composite's
 * underlying metric alarms cover the assessed Lambda function, the function is
 * effectively monitored.
 */
describe('LAMBDA-011 REQ-15 (CFN): composite alarm aggregating coverage of the assessed function', () => {
  it('passes when a composite alarm aggregates underlying metric alarms that cover the assessed Lambda function', () => {
    const stackName = 'test-stack';
    const lambdaLogicalId = 'AssessedFunction';

    const template = {
      Resources: {
        [lambdaLogicalId]: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'assessed-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::111111111111:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        // Underlying metric alarm covering the assessed function (Errors)
        ErrorsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'assessed-fn-errors',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Errors',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: { Ref: lambdaLogicalId } },
            ],
          },
        },
        // Underlying metric alarm covering the assessed function (Throttles)
        ThrottlesAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'assessed-fn-throttles',
            Namespace: 'AWS/Lambda',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:lambda-alerts'],
            MetricName: 'Throttles',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1,
            ComparisonOperator: 'GreaterThanOrEqualToThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: { Ref: lambdaLogicalId } },
            ],
          },
        },
        // Composite alarm aggregating the underlying metric alarms above
        CompositeAlarm: {
          Type: 'AWS::CloudWatch::CompositeAlarm',
          Properties: {
            AlarmName: 'assessed-fn-composite',
            AlarmRule: {
              'Fn::Sub': 'ALARM(${ErrorsAlarm}) OR ALARM(${ThrottlesAlarm})',
            },
          },
        },
      },
    } as any;

    const context: CfnContext = {
      stackName,
      template,
      resource: template.Resources[lambdaLogicalId],
      logicalId: lambdaLogicalId,
    };

    const factory = new Lambda011CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter as any, context);

    expect(result).toBeNull();
  });
});
