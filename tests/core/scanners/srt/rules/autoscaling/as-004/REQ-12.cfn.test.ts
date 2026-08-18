import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004CfnAdapterFactory();

function runControl(healthCheckType: string) {
  const template: Template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123'],
          HealthCheckType: healthCheckType,
        },
      },
    },
  } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['Asg'],
    logicalId: 'Asg',
  };

  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 CloudFormation: health check type naming multiple non-ELB services', () => {
  // Primary behavior owned by AS-004: attached to a target group, health check
  // type lists several services but none of them is Elastic Load Balancing.
  it('flags a group with a target group whose health check type is "EC2,EBS"', () => {
    const result = runControl('EC2,EBS');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-004');
    expect(result!.resourceName).toBe('Asg');
    expect(result!.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same attachment, same multi-service list, but ELB is one
  // of the named services, so load balancer health results are honoured.
  it('does not flag a group whose multi-service health check type includes ELB', () => {
    expect(runControl('EC2,ELB,EBS')).toBeNull();
  });
});
