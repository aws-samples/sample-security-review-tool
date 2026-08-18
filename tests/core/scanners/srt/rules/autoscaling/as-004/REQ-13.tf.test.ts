import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function buildGroup(healthCheckType: string): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'lattice',
    address: 'aws_autoscaling_group.lattice',
    values: {
      min_size: 1,
      max_size: 3,
      health_check_type: healthCheckType,
      traffic_source: [
        {
          identifier: 'aws_vpclattice_target_group.tg',
          type: 'vpc-lattice',
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform - VPC Lattice traffic source with VPC_LATTICE health checks', () => {
  // Primary behavior owned by this requirement: a group whose only traffic source is a
  // VPC Lattice target group and whose health_check_type is VPC_LATTICE already gets
  // application-level health checks equivalent to ELB health checks, so it must pass.
  it('does not flag a group whose only traffic_source is VPC Lattice and health_check_type is VPC_LATTICE', () => {
    expect(run(buildGroup('VPC_LATTICE'))).toBeNull();
  });

  // The service matches the token case-sensitively, so a lower-case spelling is an
  // unknown type and the group runs on instance status checks alone.
  it('flags when the VPC_LATTICE health check type is written in lower case', () => {
    const result = run(buildGroup('vpc_lattice'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
  });

  // Opposite outcome: identical VPC Lattice traffic source, but health_check_type falls back
  // to EC2 instance status checks alone - the gap this rule targets.
  it('flags the same VPC Lattice attached group when health_check_type is EC2 instance status only', () => {
    const result = run(buildGroup('EC2'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.lattice');
  });
});
