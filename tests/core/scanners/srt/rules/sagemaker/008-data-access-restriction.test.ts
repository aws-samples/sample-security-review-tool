import { describe, it, expect } from 'vitest';
import { SageMaker008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/008-data-access-restriction.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker008Rule', () => {
  const rule = new SageMaker008Rule();
  const stackName = 'test-stack';

  function createDomainResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::Domain',
      Properties: {
        AuthMode: 'IAM',
        VpcId: props.VpcId || 'vpc-12345',
        SubnetIds: props.SubnetIds || ['subnet-12345'],
        AppNetworkAccessType: props.AppNetworkAccessType || 'VpcOnly',
        ...props
      },
      LogicalId: props.LogicalId || 'TestDomain'
    };
  }

  function createNotebookInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::NotebookInstance',
      Properties: {
        InstanceType: 'ml.t3.medium',
        RoleArn: 'arn:aws:iam::123456789012:role/SageMakerRole',
        SubnetId: props.SubnetId || 'subnet-12345',
        DirectInternetAccess: props.DirectInternetAccess || 'Disabled',
        ...props
      },
      LogicalId: props.LogicalId || 'TestNotebookInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-008');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker Domain and NotebookInstance resources', () => {
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::NotebookInstance')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Domain Tests', () => {
    it('should flag Domain without VPC configuration', () => {
      const domain = createDomainResource({ 
        VpcId: undefined, 
        SubnetIds: undefined,
        LogicalId: 'NoVpcDomain'
      });
      delete domain.Properties.VpcId;
      delete domain.Properties.SubnetIds;
      
      const result = rule.evaluate(domain, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('NoVpcDomain');
      expect(result?.issue).toContain('Domain is not configured with VPC network isolation');
      expect(result?.fix).toContain('Add VpcId and SubnetIds properties');
    });

    it('should flag Domain with public internet access', () => {
      const domain = createDomainResource({ 
        AppNetworkAccessType: 'PublicInternetOnly',
        LogicalId: 'PublicDomain'
      });
      
      const result = rule.evaluate(domain, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('PublicDomain');
      expect(result?.issue).toContain('Domain allows public internet access');
      expect(result?.fix).toContain('Set AppNetworkAccessType to \'VpcOnly\'');
    });

    it('should not flag properly configured Domain', () => {
      const domain = createDomainResource();
      
      const result = rule.evaluate(domain, stackName);
      
      expect(result).toBeNull();
    });
  });

  describe('NotebookInstance Tests', () => {
    it('should flag NotebookInstance without VPC configuration', () => {
      const notebook = createNotebookInstanceResource({ 
        SubnetId: undefined,
        LogicalId: 'NoVpcNotebook'
      });
      delete notebook.Properties.SubnetId;
      
      const result = rule.evaluate(notebook, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('NoVpcNotebook');
      expect(result?.issue).toContain('NotebookInstance is not configured with VPC network isolation');
      expect(result?.fix).toContain('Add SubnetId property');
    });

    it('should flag NotebookInstance with direct internet access', () => {
      const notebook = createNotebookInstanceResource({ 
        DirectInternetAccess: 'Enabled',
        LogicalId: 'InternetNotebook'
      });
      
      const result = rule.evaluate(notebook, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('InternetNotebook');
      expect(result?.issue).toContain('NotebookInstance allows direct internet access');
      expect(result?.fix).toContain('Set DirectInternetAccess to \'Disabled\'');
    });

    it('should not flag properly configured NotebookInstance', () => {
      const notebook = createNotebookInstanceResource();
      
      const result = rule.evaluate(notebook, stackName);
      
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle resources with missing Properties', () => {
      const resource = {
        Type: 'AWS::SageMaker::Domain',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SageMaker resource allows unrestricted data access');
    });

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