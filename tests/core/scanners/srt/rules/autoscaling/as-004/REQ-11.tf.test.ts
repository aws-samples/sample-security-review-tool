import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function buildGroup(healthCheckType: string): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values: {
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.tg'],
      health_check_type: healthCheckType,
    },
  } as TerraformResource;
}

function run(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 (Terraform): health_check_type naming multiple services including ELB', () => {
  // Primary behavior owned by REQ-11: a comma-separated list that includes ELB satisfies the rule.
  it('passes a target-group-attached group whose health_check_type is "EC2,ELB"', () => {
    expect(run(buildGroup('EC2,ELB'))).toBeNull();
  });

  it('passes a target-group-attached group whose health_check_type lists ELB first ("ELB,EC2")', () => {
    expect(run(buildGroup('ELB,EC2'))).toBeNull();
  });

  // Opposite outcome: same attached group, but the list names EC2 alone, so ELB checks are off.
  it('flags the otherwise identical group whose health_check_type is only "EC2"', () => {
    const result = run(buildGroup('EC2'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
  });
});
