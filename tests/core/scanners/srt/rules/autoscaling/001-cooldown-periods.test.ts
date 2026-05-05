import { describe, it, expect } from 'vitest';
import { AS001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/001-cooldown-periods.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AS001Rule', () => {
  const rule = new AS001Rule();

  it('should pass when Cooldown is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        Cooldown: 300
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when DefaultCooldown is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        DefaultCooldown: 300
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when neither Cooldown nor DefaultCooldown is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        MinSize: 1,
        MaxSize: 3
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not have cooldown period configured');
  });

  it('should return null for non-AutoScaling resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});