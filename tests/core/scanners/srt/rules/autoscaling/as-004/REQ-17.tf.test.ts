import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function group(healthCheckType: string): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values: {
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.web'],
      health_check_type: healthCheckType,
    },
  } as TerraformResource;
}

function run(healthCheckType: string) {
  const resource = group(healthCheckType);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As004TfAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform - health check type token casing (REQ-17)', () => {
  // Primary behaviour owned by this requirement: lower-case "elb" is not the
  // recognised ELB token, so a target-group-attached group is flagged.
  it('flags a target-group-attached group whose health_check_type is lower-case "elb"', () => {
    const result = run('elb');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: same fixture, only the casing of the token changes.
  it('does not flag the same group when health_check_type is the exact token "ELB"', () => {
    expect(run('ELB')).toBeNull();
  });
});
