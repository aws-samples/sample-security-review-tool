import { describe, it, expect } from 'vitest';
import { SageMaker001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/001-vpc-required.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker001Rule', () => {
  const rule = new SageMaker001Rule();
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

  // Helper function to create SageMaker Domain test resources
  function createDomainResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::Domain',
      Properties: {
        AuthMode: 'IAM',
        DefaultUserSettings: {
          ExecutionRole: 'arn:aws:iam::123456789012:role/SageMakerRole'
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestDomain'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-001');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker NotebookInstance and Domain resources', () => {
      expect(rule.appliesTo('AWS::SageMaker::NotebookInstance')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::Model')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('NotebookInstance Tests', () => {
    it('should flag instance with missing Properties', () => {
      // Arrange
      const instance = {
        Type: 'AWS::SageMaker::NotebookInstance',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('SageMaker resource is not configured to use a VPC');
      expect(result?.fix).toContain('Configure the resource to use a VPC for improved security');
    });

    it('should flag instance with missing SubnetId property', () => {
      // Arrange
      const instance = createNotebookInstanceResource();
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::NotebookInstance');
      expect(result?.resourceName).toBe('TestNotebookInstance');
      expect(result?.issue).toContain('SageMaker resource is not configured to use a VPC');
      expect(result?.fix).toContain('Add SubnetId property to provision the notebook instance in a VPC subnet');
    });

    it('should not flag instance with valid SubnetId property', () => {
      // Arrange
      const instance = createNotebookInstanceResource({
        SubnetId: 'subnet-12345678'
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag instance with SubnetId as CloudFormation intrinsic function', () => {
      // Arrange
      const instance = createNotebookInstanceResource({
        SubnetId: { Ref: 'SubnetIdParameter' }
      });
      
      // Act
      const result = rule.evaluate(instance, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Domain Tests', () => {
    it('should flag domain with missing Properties', () => {
      // Arrange
      const domain = {
        Type: 'AWS::SageMaker::Domain',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('MissingProperties');
      expect(result?.issue).toContain('SageMaker resource is not configured to use a VPC');
      expect(result?.fix).toContain('Configure the resource to use a VPC for improved security');
    });

    it('should flag domain with missing VpcId property', () => {
      // Arrange
      const domain = createDomainResource();
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker resource is not configured to use a VPC');
      expect(result?.fix).toContain('Add VpcId property to provision the domain in a VPC');
    });

    it('should flag domain with VpcId but missing SubnetIds property', () => {
      // Arrange
      const domain = createDomainResource({
        VpcId: 'vpc-12345678'
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker resource is not configured to use a VPC');
      expect(result?.fix).toContain('Add SubnetIds property along with VpcId to properly configure VPC networking');
    });

    it('should not flag domain with valid VpcId and SubnetIds properties', () => {
      // Arrange
      const domain = createDomainResource({
        VpcId: 'vpc-12345678',
        SubnetIds: ['subnet-12345678', 'subnet-87654321']
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull();
    });

    it('should not flag domain with VpcId as CloudFormation intrinsic function', () => {
      // Arrange
      const domain = createDomainResource({
        VpcId: { Ref: 'VpcIdParameter' },
        SubnetIds: ['subnet-12345678', 'subnet-87654321']
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      // Act
      const result = rule.evaluate(resource, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });
});
