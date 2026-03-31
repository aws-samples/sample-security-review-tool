import { describe, it, expect } from 'vitest';
import { SageMaker009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/009-no-root-access.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker009Rule', () => {
  const rule = new SageMaker009Rule();
  const stackName = 'test-stack';

  // Helper function to create SageMaker NotebookInstance test resources
  function createNotebookInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::NotebookInstance',
      Properties: {
        InstanceType: 'ml.t3.medium',
        RoleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
        ...props
      },
      LogicalId: props.LogicalId || 'TestNotebookInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-009');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker NotebookInstance resources only', () => {
      expect(rule.appliesTo('AWS::SageMaker::NotebookInstance')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('NotebookInstance Tests', () => {
    it('should flag instance with missing Properties', () => {
      const instance = {
        Type: 'AWS::SageMaker::NotebookInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('SageMaker resource has root access enabled when not required');
      expect(result?.fix).toContain('Configure RootAccess property to \'Disabled\'');
    });

    it('should flag instance with missing RootAccess property (defaults to Enabled)', () => {
      const instance = createNotebookInstanceResource();
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has root access enabled when not required');
      expect(result?.fix).toContain('Add RootAccess property and set it to \'Disabled\'. Use lifecycle configurations for software installation instead.');
    });

    it('should flag instance with RootAccess set to Enabled', () => {
      const instance = createNotebookInstanceResource({
        RootAccess: 'Enabled'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has root access enabled when not required');
      expect(result?.fix).toContain('Set RootAccess property to \'Disabled\'. Use lifecycle configurations for software installation instead.');
    });

    it('should not flag instance with RootAccess set to Disabled', () => {
      const instance = createNotebookInstanceResource({
        RootAccess: 'Disabled'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).toBeNull();
    });

    it('should handle case variations for RootAccess value', () => {
      const instance = createNotebookInstanceResource({
        RootAccess: 'disabled'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).toBeNull();
    });

    it('should flag instance with RootAccess as CloudFormation intrinsic function', () => {
      const instance = createNotebookInstanceResource({
        RootAccess: { Ref: 'RootAccessParameter' }
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has root access enabled when not required');
      expect(result?.fix).toContain('Set RootAccess property to an explicit string value');
    });

    it('should flag instance with RootAccess set to unexpected value', () => {
      const instance = createNotebookInstanceResource({
        RootAccess: 'SomeOtherValue'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker resource has root access enabled when not required');
      expect(result?.fix).toContain('Set RootAccess property to \'Disabled\'. Use lifecycle configurations for software installation instead.');
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      const result = rule.evaluate(resource, stackName);
      
      expect(result).toBeNull();
    });
  });
});