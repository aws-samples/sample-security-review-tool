import { describe, it, expect } from 'vitest';
import { SageMaker010Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/010-role-reuse.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker010Rule', () => {
  const rule = new SageMaker010Rule();
  const stackName = 'test-stack';

  function createDomainResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::Domain',
      Properties: {
        AuthMode: 'IAM',
        DefaultUserSettings: {
          ExecutionRole: props.ExecutionRole || 'arn:aws:iam::123456789012:role/SageMakerDomainRole',
          ...props.DefaultUserSettings
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestDomain'
    };
  }

  function createUserProfileResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::UserProfile',
      Properties: {
        DomainId: 'domain-id',
        UserSettings: {
          ExecutionRole: props.ExecutionRole || 'arn:aws:iam::123456789012:role/SageMakerUserProfileRole',
          ...props.UserSettings
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestUserProfile'
    };
  }

  function createNotebookInstanceResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::NotebookInstance',
      Properties: {
        InstanceType: 'ml.t3.medium',
        RoleArn: props.RoleArn || 'arn:aws:iam::123456789012:role/SageMakerNotebookRole',
        ...props
      },
      LogicalId: props.LogicalId || 'TestNotebookInstance'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-010');
    });

    it('should have MEDIUM priority', () => {
      expect(rule.priority).toBe('MEDIUM');
    });

    it('should apply to SageMaker resources', () => {
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::UserProfile')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::NotebookInstance')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::Model')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Role Reuse Detection Tests', () => {
    it('should flag when Domain and NotebookInstance share the same role', () => {
      const sharedRole = 'arn:aws:iam::123456789012:role/SharedSageMakerRole';
      const domain = createDomainResource({ 
        ExecutionRole: sharedRole, 
        LogicalId: 'Domain1' 
      });
      const notebook = createNotebookInstanceResource({ 
        RoleArn: sharedRole, 
        LogicalId: 'Notebook1' 
      });
      const allResources = [domain, notebook];
      
      const result = rule.evaluate(domain, stackName, allResources);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('Domain1');
      expect(result?.issue).toContain('Role \'arn:aws:iam::123456789012:role/SharedSageMakerRole\' is shared across multiple SageMaker features');
      expect(result?.fix).toContain('Create IAM role \'Domain1DomainRole\'');
      expect(result?.fix).toContain('Update Domain1.Properties.DefaultUserSettings.ExecutionRole');
      expect(result?.fix).toContain('Create IAM role \'Notebook1NotebookRole\'');
      expect(result?.fix).toContain('Update Notebook1.Properties.RoleArn');
      expect(result?.fix).toContain('Use AWS SageMaker Role Manager for domains.');
    });

    it('should not flag when resources have unique roles', () => {
      const domain = createDomainResource({ LogicalId: 'DomainUnique' });
      const userProfile = createUserProfileResource({ LogicalId: 'UserProfileUnique' });
      const notebook = createNotebookInstanceResource({ LogicalId: 'NotebookUnique' });
      const allResources = [domain, userProfile, notebook];
      
      const domainResult = rule.evaluate(domain, stackName, allResources);
      const userProfileResult = rule.evaluate(userProfile, stackName, allResources);
      const notebookResult = rule.evaluate(notebook, stackName, allResources);
      
      expect(domainResult).toBeNull();
      expect(userProfileResult).toBeNull();
      expect(notebookResult).toBeNull();
    });

    it('should not flag when multiple resources of the same type share a role', () => {
      const sharedRole = 'arn:aws:iam::123456789012:role/SharedDomainRole';
      const domain1 = createDomainResource({ 
        ExecutionRole: sharedRole, 
        LogicalId: 'Domain1' 
      });
      const domain2 = createDomainResource({ 
        ExecutionRole: sharedRole, 
        LogicalId: 'Domain2' 
      });
      const allResources = [domain1, domain2];
      
      const result1 = rule.evaluate(domain1, stackName, allResources);
      const result2 = rule.evaluate(domain2, stackName, allResources);
      
      expect(result1).toBeNull();
      expect(result2).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle resources with missing Properties', () => {
      const resource = {
        Type: 'AWS::SageMaker::Domain',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName, [resource]);
      
      expect(result).toBeNull();
    });

    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };
      
      const result = rule.evaluate(resource, stackName, [resource]);
      
      expect(result).toBeNull();
    });
  });
});