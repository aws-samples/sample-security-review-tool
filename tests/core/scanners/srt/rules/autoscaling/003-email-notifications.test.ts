import { describe, it, expect } from 'vitest';
import { AS003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/003-email-notifications.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AS003Rule', () => {
  const rule = new AS003Rule();

  it('should pass when NotificationConfigurations is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        NotificationConfigurations: [
          {
            TopicARN: 'arn:aws:sns:us-east-1:123456789012:my-topic',
            NotificationTypes: ['autoscaling:EC2_INSTANCE_LAUNCH']
          }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when NotificationConfigurations is not configured', () => {
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
    expect(result?.issue).toContain('does not have notification configurations');
  });

  it('should fail when NotificationConfigurations is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        NotificationConfigurations: []
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not have notification configurations');
  });

  it('should fail when NotificationConfigurations is not an array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        NotificationConfigurations: 'invalid'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not have notification configurations');
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