import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function run(group: TerraformResource, allResources: TerraformResource[] = [group]) {
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  return as004Control.run(factory.bind(context), context);
}

function group(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: { name: 'app-asg', min_size: 1, max_size: 3, ...values },
  } as unknown as TerraformResource;
}

describe('AS-004 Terraform — REQ-04 unattached group with EC2 health checks', () => {
  // Primary behavior owned by this requirement: no load_balancers,
  // no target_group_arns, no traffic_source blocks and no external attachment
  // resources, so EC2 instance status checks are the complete health signal.
  it('passes a group with no attachments and health_check_type = "EC2"', () => {
    const result = run(group({ health_check_type: 'EC2' }));

    expect(result).toBeNull();
  });

  it('passes a group with no attachments and health_check_type omitted (provider default is EC2)', () => {
    const result = run(group({}));

    expect(result).toBeNull();
  });

  it('passes a group with no attachments when other attachment resources target a different group', () => {
    const target = group({ health_check_type: 'EC2' });
    const other: TerraformResource = {
      type: 'aws_autoscaling_attachment',
      name: 'other',
      address: 'aws_autoscaling_attachment.other',
      values: { autoscaling_group_name: 'aws_autoscaling_group.unrelated', lb_target_group_arn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc' },
    } as unknown as TerraformResource;

    expect(run(target, [target, other])).toBeNull();
  });

  // Opposite outcome: change only the attachment, keep EC2 health checks, and
  // the group becomes in scope and non-compliant (AS-004 primary finding).
  it('flags an otherwise identical group that IS attached via target_group_arns', () => {
    const result = run(group({
      health_check_type: 'EC2',
      target_group_arns: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/abc'],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
