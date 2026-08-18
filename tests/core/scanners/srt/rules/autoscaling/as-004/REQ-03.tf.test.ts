import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const unresolved = (ref: string): string => `__unresolved__:${ref}`;

function group(healthCheckType: unknown): TerraformResource {
  const values: Record<string, unknown> = {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
  };
  if (healthCheckType !== undefined) values['health_check_type'] = healthCheckType;
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;
}

const trafficSourceAttachment: TerraformResource = {
  type: 'aws_autoscaling_traffic_source_attachment',
  name: 'tg',
  address: 'aws_autoscaling_traffic_source_attachment.tg',
  values: {
    autoscaling_group_name: 'aws_autoscaling_group.app',
    traffic_source: [{ identifier: 'aws_lb_target_group.app', type: 'elbv2' }],
  },
} as TerraformResource;

function run(asg: TerraformResource): ScanResult | null {
  const allResources = [asg, trafficSourceAttachment];
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources,
  };
  const factory = new As004TfAdapterFactory();
  expect(factory.appliesTo(asg.type)).toBe(true);
  return as004Control.run(factory.bind(context), context);
}

/**
 * REQ-03 owns this behavior: a group wired to a target group through a traffic
 * source attachment, whose health check type is EC2 instance status only, must
 * be flagged.
 */
describe('AS-004 REQ-03 (Terraform): traffic source attachment with EC2-only health checks', () => {
  it('flags a group targeted by a traffic source attachment when health_check_type is EC2', () => {
    const result = run(group('EC2'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toMatch(/EC2 instance status/i);
  });

  // Opposite outcome: identical traffic source attachment, but the health check
  // type meets the standard (ELB), so there is nothing to flag.
  it('does not flag the same attachment when health_check_type is ELB', () => {
    expect(run(group('ELB'))).toBeNull();
  });

  it('does not flag when health_check_type comes from an unresolved variable', () => {
    expect(run(group(unresolved('var.health_check_type')))).toBeNull();
  });
});
