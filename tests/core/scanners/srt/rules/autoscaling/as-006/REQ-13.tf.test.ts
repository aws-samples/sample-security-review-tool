import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as unknown as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform: subnets whose Availability Zones are not knowable at analysis time', () => {
  // Primary behaviour owned by REQ-13: two literal, pre-existing subnet IDs -> zones unknown -> no finding.
  it('passes an Auto Scaling group that lists two literal subnet IDs not declared in the project', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        vpc_zone_identifier: ['subnet-0aa11bb22cc33dd44', 'subnet-0ee55ff66gg77hh88'],
      },
    };

    expect(scan(asg, [asg])).toBeNull();
  });

  // Opposite outcome: same two-subnet shape, but the subnets ARE declared here and share one zone.
  it('flags an Auto Scaling group whose two declared subnets both sit in the same Availability Zone', () => {
    const subnetOne: TerraformResource = {
      type: 'aws_subnet',
      name: 'one',
      address: 'aws_subnet.one',
      values: { cidr_block: '10.0.1.0/24', availability_zone: 'us-east-1a' },
    };
    const subnetTwo: TerraformResource = {
      type: 'aws_subnet',
      name: 'two',
      address: 'aws_subnet.two',
      values: { cidr_block: '10.0.2.0/24', availability_zone: 'us-east-1a' },
    };
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        vpc_zone_identifier: ['aws_subnet.one', 'aws_subnet.two'],
      },
    };

    const result = scan(asg, [asg, subnetOne, subnetTwo]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
