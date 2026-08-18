import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function buildGroup(healthCheckType: string): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      HealthCheckType: healthCheckType,
      TrafficSources: [
        {
          Identifier: 'arn:aws:vpc-lattice:us-east-1:123456789012:targetgroup/tg-0123456789abcdef0',
          Type: 'vpc-lattice',
        },
      ],
    },
  } as unknown as Resource;
}

function run(resource: Resource) {
  const template: Template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 CloudFormation - VPC Lattice traffic source with VPC_LATTICE health checks', () => {
  // Primary behavior owned by this requirement: a group whose only traffic source is a
  // VPC Lattice target group and whose health check type is VPC_LATTICE already gets
  // application-level health checks equivalent to ELB health checks, so it must pass.
  it('does not flag a group whose only traffic source is VPC Lattice and health check type is VPC_LATTICE', () => {
    expect(run(buildGroup('VPC_LATTICE'))).toBeNull();
  });

  // The service matches the token case-sensitively, so a lower-case spelling is an
  // unknown type and the group runs on instance status checks alone.
  it('flags when the VPC_LATTICE health check type is written in lower case', () => {
    const result = run(buildGroup('vpc_lattice'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
  });

  // Opposite outcome: same traffic source attachment, but the health check type falls back
  // to EC2 instance status checks alone - the gap this rule targets.
  it('flags the same VPC Lattice attached group when the health check type is EC2 instance status only', () => {
    const result = run(buildGroup('EC2'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('Asg');
  });
});
