import { describe, it, expect } from 'vitest';
import { Lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 REQ-03 (CloudFormation): Alarm exists but uses non-Lambda metric namespace', () => {
  it('should flag a Lambda function when the only alarm uses a metric namespace unrelated to Lambda', () => {
    const template: any = {
      Resources: {
        MyLambda: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        UnrelatedAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'unrelated-alarm',
            // Namespace is NOT AWS/Lambda - this alarm cannot be monitoring a Lambda function
            Namespace: 'AWS/EC2',
            MetricName: 'CPUUtilization',
            Statistic: 'Average',
            Period: 300,
            EvaluationPeriods: 1,
            Threshold: 80,
            ComparisonOperator: 'GreaterThanThreshold',
            Dimensions: [
              { Name: 'InstanceId', Value: 'i-0123456789abcdef0' },
            ],
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.MyLambda,
      logicalId: 'MyLambda',
    };

    const factory = new Lambda011CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const control = new Lambda011Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-011');
    expect(result?.resourceName).toBe('MyLambda');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.status).toBe('Open');
  });
});
