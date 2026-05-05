import { describe, it, expect } from 'vitest';
import { AS002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/002-health-checks.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AS002Rule', () => {
  const rule = new AS002Rule();

  it('should pass when ELB health check with grace period is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        HealthCheckType: 'ELB',
        HealthCheckGracePeriod: 300
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when HealthCheckType is EC2', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        HealthCheckType: 'EC2'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not have health check configuration');
  });

  it('should fail when no HealthCheckType is configured', () => {
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
    expect(result?.issue).toContain('does not have health check configuration');
  });

  it('should fail when ELB health check is configured without grace period', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        HealthCheckType: 'ELB'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not have health check configuration');
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