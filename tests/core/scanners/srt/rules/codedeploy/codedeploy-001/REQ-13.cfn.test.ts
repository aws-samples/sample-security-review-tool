import { describe, expect, it } from 'vitest';
import { codedeploy001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.control.js';
import { Codedeploy001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.cfn.js';
import type { Codedeploy001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codedeploy/codedeploy-001/codedeploy-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::CodeDeploy::DeploymentGroup';
const LOGICAL_ID = 'DeploymentGroup';

function scan(resource: Resource): ScanResult | null {
  const template = {
    Resources: { [LOGICAL_ID]: resource },
  } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new Codedeploy001CfnAdapterFactory().bind(context) as Codedeploy001Adapter;
  return codedeploy001Control.run(adapter, context);
}

describe('CODEDEPLOY-001 (CloudFormation) - alarm configuration gated by an unresolvable condition', () => {
  // Primary behaviour owned by this requirement: the whole AlarmConfiguration
  // property is produced by an Fn::If whose condition is fed by a deployment-time
  // parameter. One resolution attaches alarms, the other omits the property
  // entirely, so the scanner cannot assert a breach.
  it('does not flag when the presence of AlarmConfiguration depends on an unresolved condition', () => {
    const result = scan({
      Type: RESOURCE_TYPE,
      Properties: {
        ApplicationName: 'app',
        ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
        AlarmConfiguration: {
          'Fn::If': [
            'MonitorDeployments',
            {
              Enabled: true,
              Alarms: [{ Name: 'deployment-errors' }],
            },
            { Ref: 'AWS::NoValue' },
          ],
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical deployment group, except the condition is gone and
  // the alarm configuration is stated outright with monitoring on but no alarms.
  // The scanner can now see the state, so it must flag it.
  it('flags when the same alarm configuration is stated outright and names no alarms', () => {
    const result = scan({
      Type: RESOURCE_TYPE,
      Properties: {
        ApplicationName: 'app',
        ServiceRoleArn: 'arn:aws:iam::123456789012:role/CodeDeployRole',
        AlarmConfiguration: {
          Enabled: true,
          Alarms: [],
        },
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEDEPLOY-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });
});
