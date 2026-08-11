import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-011) — CloudFormation
 *
 * Scenario: A CloudWatch alarm targets the assessed Lambda function on a Lambda metric,
 * but the alarm has NO alarm actions configured.
 *
 * Expected behavior: FLAG.
 *
 * An alarm with no actions notifies nobody when it breaches, so it is not monitoring
 * coverage. AWS treats it as non-compliant via the managed Config rule
 * cloudwatch-alarm-action-check. This is REQ-05's defect reached another way — actions
 * present but disabled there, no actions at all here — so the verdict matches.
 */
describe('LAMBDA-011 [CFN] — REQ-13: alarm targeting the function with no alarm actions', () => {
  const factory = new Lambda011CfnAdapterFactory();

  const lambdaFunction = {
    Type: 'AWS::Lambda::Function',
    Properties: {
      FunctionName: 'my-monitored-function',
      Runtime: 'nodejs20.x',
      Handler: 'index.handler',
      Role: 'arn:aws:iam::123456789012:role/lambda-role',
      Code: { ZipFile: 'exports.handler = async () => {};' },
    },
  };

  const alarm = (properties: Record<string, unknown>) => ({
    Type: 'AWS::CloudWatch::Alarm',
    Properties: {
      Namespace: 'AWS/Lambda',
      MetricName: 'Errors',
      Statistic: 'Sum',
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 1,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
      Dimensions: [{ Name: 'FunctionName', Value: 'my-monitored-function' }],
      ...properties,
    },
  });

  const evaluate = (alarmProperties: Record<string, unknown>) => {
    const template = {
      Resources: { AssessedFunction: lambdaFunction, ErrorsAlarm: alarm(alarmProperties) },
    } as unknown as Template;

    const resource = template.Resources!['AssessedFunction'];
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'AssessedFunction' };

    return lambda011Control.run(factory.bind(context), context);
  };

  it('flags when the alarm has no AlarmActions property at all', () => {
    expect(evaluate({})?.check_id).toBe('LAMBDA-011');
  });

  it('flags when AlarmActions is present but empty', () => {
    expect(evaluate({ AlarmActions: [] })?.check_id).toBe('LAMBDA-011');
  });

  it('flags when only OKActions is configured, since no alarm-state action exists', () => {
    expect(evaluate({ OKActions: ['arn:aws:sns:us-east-1:123456789012:recovered'] })?.check_id).toBe('LAMBDA-011');
  });

  it('does NOT flag once an AlarmActions target is configured (REQ-16)', () => {
    expect(evaluate({ AlarmActions: ['arn:aws:sns:us-east-1:123456789012:alerts'] })).toBeNull();
  });

  it('does NOT flag when AlarmActions is an unresolvable intrinsic', () => {
    expect(evaluate({ AlarmActions: { Ref: 'AlertTopicArnParameter' } })).toBeNull();
  });
});
