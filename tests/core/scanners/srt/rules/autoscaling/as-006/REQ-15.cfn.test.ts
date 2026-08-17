import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (AS-006) — Availability Zones supplied entirely by a deployment-time input,
 * with no subnets referenced, must NOT be reported: the scanner cannot know how many
 * zones the input supplies, so the breach is not established.
 */

const factory = new As006CfnAdapterFactory();

function scan(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation — Availability Zones from a deployment-time input', () => {
  it('does not report an Auto Scaling group whose AvailabilityZones come from a template parameter with no default and which references no subnets', () => {
    // Authored as: AvailabilityZones: !Ref AvailabilityZonesParam
    // A parameter with no Default resolves to the placeholder string "DEFAULT" during
    // preprocessing, so the real zone list is only known at deployment time.
    const template = {
      Parameters: {
        AvailabilityZonesParam: { Type: 'CommaDelimitedList' },
      },
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            AvailabilityZones: 'DEFAULT',
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Asg')).toBeNull();
  });

  it('does not report an Auto Scaling group whose AvailabilityZones list is an unresolved intrinsic over a deployment-time input', () => {
    // Authored as: AvailabilityZones: !Split [",", !Ref AvailabilityZonesParam]
    // Fn::Split is never resolved by preprocessing, so the rule sees an opaque object.
    const template = {
      Parameters: {
        AvailabilityZonesParam: { Type: 'String' },
      },
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            AvailabilityZones: { 'Fn::Split': [',', 'DEFAULT'] },
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Asg')).toBeNull();
  });

  // Opposite outcome — nearest input that flips the verdict. The zone list is present but
  // is a known literal naming exactly one zone, which the single-availability-zone
  // requirement owns (AS-006 primary behavior, not this scenario).
  it('reports an Auto Scaling group whose AvailabilityZones list is a known literal naming one zone and references no subnets', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            AvailabilityZones: ['us-east-1a'],
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'Asg');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
  });
});
