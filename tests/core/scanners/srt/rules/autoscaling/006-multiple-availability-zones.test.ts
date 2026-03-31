import { describe, it, expect } from 'vitest';
import { AS006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/006-multiple-availability-zones.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AS006Rule', () => {
  const rule = new AS006Rule();

  it('should pass when multiple AvailabilityZones are configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        AvailabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when multiple VPCZoneIdentifier subnets are configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        VPCZoneIdentifier: ['subnet-12345', 'subnet-67890']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when only one AvailabilityZone is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        AvailabilityZones: ['us-east-1a']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not span multiple Availability Zones');
  });

  it('should fail when only one VPCZoneIdentifier subnet is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        VPCZoneIdentifier: ['subnet-12345']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not span multiple Availability Zones');
  });

  it('should fail when neither AvailabilityZones nor VPCZoneIdentifier is configured', () => {
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
    expect(result?.issue).toContain('does not span multiple Availability Zones');
  });

  it('should fail when AvailabilityZones is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        AvailabilityZones: []
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not span multiple Availability Zones');
  });

  it('should fail when VPCZoneIdentifier is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        VPCZoneIdentifier: []
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('does not span multiple Availability Zones');
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