import { describe, it, expect } from 'vitest';
import { SageMaker003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/003-no-direct-internet.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker003Rule', () => {
  const rule = new SageMaker003Rule();
  const stackName = 'test-stack';

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
      expect(rule.id).toBe('SAGEMAKER-003');
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
      expect(result?.issue).toContain('SageMaker resource has direct internet access enabled without proper authentication strategy');
      expect(result?.fix).toContain('Configure DirectInternetAccess property to \'Disabled\'');
    });

    it('should flag instance with missing DirectInternetAccess property (defaults to Enabled)', () => {
      const instance = createNotebookInstanceResource();
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has direct internet access enabled without proper authentication strategy');
      expect(result?.fix).toContain('Add DirectInternetAccess property and set it to \'Disabled\'. Implement federated authentication for users.');
    });

    it('should flag instance with DirectInternetAccess set to Enabled', () => {
      const instance = createNotebookInstanceResource({
        DirectInternetAccess: 'Enabled'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has direct internet access enabled without proper authentication strategy');
      expect(result?.fix).toContain('Set DirectInternetAccess property to \'Disabled\'. Use federated authentication and well-defined access control strategy.');
    });

    it('should not flag instance with DirectInternetAccess set to Disabled', () => {
      const instance = createNotebookInstanceResource({
        DirectInternetAccess: 'Disabled'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).toBeNull();
    });

    it('should flag instance with DirectInternetAccess as CloudFormation intrinsic function', () => {
      const instance = createNotebookInstanceResource({
        DirectInternetAccess: { Ref: 'DirectInternetAccessParameter' }
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource has direct internet access enabled without proper authentication strategy');
      expect(result?.fix).toContain('Set DirectInternetAccess property to an explicit string value');
    });

    it('should flag instance with DirectInternetAccess set to unexpected value', () => {
      const instance = createNotebookInstanceResource({
        DirectInternetAccess: 'SomeOtherValue'
      });
      
      const result = rule.evaluate(instance, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker resource has direct internet access enabled without proper authentication strategy');
      expect(result?.fix).toContain('Set DirectInternetAccess property to \'Disabled\'. Use federated authentication and well-defined access control strategy.');
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