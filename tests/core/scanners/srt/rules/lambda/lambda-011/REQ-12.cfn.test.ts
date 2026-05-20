import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (CloudFormation): An alarm targets the assessed Lambda function on a Lambda
 * namespace metric that is NOT one of the commonly recommended reliability metrics
 * (Errors, Throttles, Duration, ConcurrentExecutions). Here the alarm monitors
 * `Invocations`. The rule's intent is to ensure monitoring coverage exists; any alarm
 * on the AWS/Lambda namespace targeting the function provides observability and
 * therefore satisfies the requirement.
 *
 * Expected behavior: PASS (no finding produced).
 */
describe('LAMBDA-011 (CFN) REQ-12: alarm on a non-recommended Lambda metric still satisfies monitoring requirement', () => {
  it('produces no finding when an alarm targets the assessed function on the Invocations metric', () => {
    const template: Template = {
      Resources: {
        AssessedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-assessed-function',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Runtime: 'nodejs20.x',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        InvocationsAlarm: {
          Type: 'AWS::CloudWatch::Alarm',
          Properties: {
            AlarmName: 'my-assessed-function-invocations',
            Namespace: 'AWS/Lambda',
            // Not one of the commonly recommended reliability metrics:
            MetricName: 'Invocations',
            Statistic: 'Sum',
            Period: 60,
            EvaluationPeriods: 1,
            Threshold: 1000,
            ComparisonOperator: 'GreaterThanThreshold',
            Dimensions: [
              { Name: 'FunctionName', Value: 'my-assessed-function' },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda011CfnAdapterFactory();
    const resource = template.Resources!['AssessedFunction'];
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'AssessedFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
