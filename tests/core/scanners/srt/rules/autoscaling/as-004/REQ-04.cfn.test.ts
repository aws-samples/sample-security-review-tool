import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { Asg: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 CloudFormation — REQ-04 unattached group with EC2 health checks', () => {
  // Primary behavior owned by this requirement: a group with no load balancer
  // names, no target groups and no traffic sources is out of scope, so EC2
  // instance status checks are sufficient.
  it('passes a group with no attachments and HealthCheckType EC2', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      HealthCheckType: 'EC2',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).toBeNull();
  });

  it('passes a group with no attachments and no HealthCheckType at all (service default is EC2)', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: change only the attachment, keep EC2 health checks, and
  // the group becomes in scope and non-compliant (AS-004 primary finding).
  it('flags an otherwise identical group that IS attached to a load balancer', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      HealthCheckType: 'EC2',
      AvailabilityZones: ['us-east-1a'],
      LoadBalancerNames: ['my-classic-elb'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
