import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'as-006-project';
const factory = new As006TfAdapterFactory();
const unresolved = (reference: string): string => `__unresolved__:${reference}`;

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: PROJECT_NAME, resource, allResources };
  return as006Control.run(factory.bind(context), context);
}

/**
 * REQ-16 owns this behavior: when the Auto Scaling group's subnet list comes from an input
 * variable with no reachable default, the subnet count and their Availability Zones are
 * unknown at analysis time, so no breach can be asserted.
 */
describe('AS-006 Terraform - subnet list supplied at deployment time', () => {
  it('passes when vpc_zone_identifier comes entirely from an unresolved input variable and no availability_zones are named', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        vpc_zone_identifier: unresolved('var.subnet_ids'),
      },
    };

    expect(scan(asg)).toBeNull();
  });

  // Opposite outcome: identical shape, but the subnet list is known at analysis time and
  // pins the group to a single Availability Zone (owned by the single-subnet scenario).
  it('flags a group whose vpc_zone_identifier is a known list naming only one subnet', () => {
    const subnet: TerraformResource = {
      type: 'aws_subnet',
      name: 'a',
      address: 'aws_subnet.a',
      values: { availability_zone: 'us-east-1a', cidr_block: '10.0.1.0/24' },
    };
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        vpc_zone_identifier: ['aws_subnet.a'],
      },
    };

    const result = scan(asg, [asg, subnet]);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
