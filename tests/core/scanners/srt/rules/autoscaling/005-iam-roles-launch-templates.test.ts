import { describe, it, expect } from 'vitest';
import { AUTOSCALING001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/005-iam-roles-launch-templates.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AUTOSCALING001Rule', () => {
  const rule = new AUTOSCALING001Rule();

  describe('AutoScaling Group evaluation', () => {
    it('should pass when LaunchTemplate is configured with LaunchTemplateId', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        LogicalId: 'TestASG',
        Properties: {
          LaunchTemplate: {
            LaunchTemplateId: 'lt-12345',
            Version: '1'
          }
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    });

    it('should pass when LaunchTemplate is configured with LaunchTemplateName', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        LogicalId: 'TestASG',
        Properties: {
          LaunchTemplate: {
            LaunchTemplateName: 'my-launch-template',
            Version: '1'
          }
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    });

    it('should pass when MixedInstancesPolicy is configured', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        LogicalId: 'TestASG',
        Properties: {
          MixedInstancesPolicy: {
            LaunchTemplate: {
              LaunchTemplateSpecification: {
                LaunchTemplateId: 'lt-12345',
                Version: '1'
              }
            }
          }
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    });

    it('should fail when neither LaunchTemplate nor MixedInstancesPolicy is configured', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        LogicalId: 'TestASG',
        Properties: {
          LaunchConfigurationName: 'my-launch-config'
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Add LaunchTemplate property for granular IAM permissions');
    });

    it('should fail when LaunchTemplate has no identifier', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        LogicalId: 'TestASG',
        Properties: {
          LaunchTemplate: {
            Version: '1'
          }
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Add LaunchTemplateId or LaunchTemplateName to LaunchTemplate property');
    });
  });

  it('should return null for non-supported resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});