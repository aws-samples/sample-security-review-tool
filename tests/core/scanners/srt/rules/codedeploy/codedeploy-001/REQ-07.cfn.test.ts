import { describe, it, expect } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codedeploy001CfnAdapterFactory();

/**
 * Builds a template containing a CloudWatch alarm resource and a deployment group
 * whose AlarmConfiguration is given by the caller.
 *
 * Note: fixtures are written in their POST-parseCfnTemplate form. `!Ref DeploymentAlarm`
 * resolves to the logical id string "DeploymentAlarm".
 */
function buildTemplate(alarmConfiguration: unknown): Template {
  return {
    Resources: {
      DeploymentAlarm: {
        Type: 'AWS::CloudWatch::Alarm',
        Properties: {
          AlarmName: 'DeploymentAlarm',
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          MetricName: 'Errors',
          Namespace: 'AWS/Lambda',
          Threshold: 1,
        },
      },
      DeploymentGroup: {
        Type: 'AWS::CodeDeploy::DeploymentGroup',
        Properties: {
          ApplicationName: 'MyApplication',
          ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
          ...(alarmConfiguration === undefined ? {} : { AlarmConfiguration: alarmConfiguration }),
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['DeploymentGroup'],
    logicalId: 'DeploymentGroup',
  };
  const adapter = factory.bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (CloudFormation) - enabled AlarmConfiguration naming a template alarm', () => {
  // Primary behavior owned by this requirement: an enabled AlarmConfiguration whose
  // Alarms list names a CloudWatch alarm declared in the same template must pass.
  it('does not report a finding when the enabled AlarmConfiguration names a CloudWatch alarm from the template', () => {
    const template = buildTemplate({
      Enabled: true,
      Alarms: [{ Name: 'DeploymentAlarm' }],
    });

    expect(runControl(template)).toBeNull();
  });

  it('applies to AWS::CodeDeploy::DeploymentGroup resources', () => {
    expect(factory.appliesTo('AWS::CodeDeploy::DeploymentGroup')).toBe(true);
  });

  // Opposite outcome: identical template except the enabled AlarmConfiguration
  // names no alarm at all, so nothing monitors the deployment.
  it('reports a finding when the enabled AlarmConfiguration lists no alarms', () => {
    const template = buildTemplate({
      Enabled: true,
      Alarms: [],
    });

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe('DeploymentGroup');
  });
});
