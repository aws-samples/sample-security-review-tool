import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-006 — Auto Scaling groups must span at least two Availability Zones.
 *
 * REQ-17: an Auto Scaling group referencing two subnets declared in the same template
 * whose Availability Zone assignments come from deployment-time inputs must NOT be flagged:
 * the inputs can legitimately resolve to two distinct zones, so a breach is not certain.
 *
 * Note on preprocessing: `!Ref SubnetA` resolves to the logical id string "SubnetA", and a
 * `!Ref` to a template Parameter without a Default resolves to the string "DEFAULT" — the
 * placeholder for a value only supplied at deployment time. The fixtures below are written
 * in post-preprocessing form.
 */

const factory = new As006CfnAdapterFactory();

function run(template: Template, logicalId: string): ScanResult | null {
  const resources = template.Resources as Record<string, Resource>;
  const resource = resources[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return as006Control.run(factory.bind(context), context);
}

function template(zoneA: string, zoneB: string): Template {
  return {
    Parameters: {
      SubnetAZoneParam: { Type: 'String' },
      SubnetBZoneParam: { Type: 'String' },
    },
    Resources: {
      SubnetA: {
        Type: 'AWS::EC2::Subnet',
        Properties: { VpcId: 'Vpc', CidrBlock: '10.0.1.0/24', AvailabilityZone: zoneA },
      },
      SubnetB: {
        Type: 'AWS::EC2::Subnet',
        Properties: { VpcId: 'Vpc', CidrBlock: '10.0.2.0/24', AvailabilityZone: zoneB },
      },
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '2',
          // !Ref SubnetA / !Ref SubnetB after preprocessing
          VPCZoneIdentifier: ['SubnetA', 'SubnetB'],
        },
      },
    },
  } as unknown as Template;
}

describe('AS-006 CloudFormation — subnet Availability Zones supplied at deployment time', () => {
  it('does not flag an Auto Scaling group whose two subnets take their zones from deployment-time inputs', () => {
    // Both subnet AvailabilityZone values came from Parameters without defaults -> "DEFAULT".
    const result = run(template('DEFAULT', 'DEFAULT'), 'Asg');

    expect(result).toBeNull();
  });

  it('flags the same group when both subnets declare the same literal Availability Zone (owned by the single-zone requirement)', () => {
    // Nearest input that flips the verdict: the zone values are known and identical.
    const result = run(template('us-east-1a', 'us-east-1a'), 'Asg');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
  });

  it('does not flag the same group when the two subnets declare two distinct literal Availability Zones', () => {
    const result = run(template('us-east-1a', 'us-east-1b'), 'Asg');

    expect(result).toBeNull();
  });
});
