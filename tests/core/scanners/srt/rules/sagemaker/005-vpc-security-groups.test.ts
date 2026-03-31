import { describe, it, expect } from 'vitest';
import { SageMaker005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/005-vpc-security-groups.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker005Rule', () => {
  const rule = new SageMaker005Rule();
  const stackName = 'test-stack';

  function createDomainResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::Domain',
      Properties: {
        AuthMode: 'IAM',
        AppNetworkAccessType: props.AppNetworkAccessType || 'VpcOnly',
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
          SecurityGroups: props.SecurityGroups || ['sg-12345'],
          ...props.UserSettings
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestUserProfile'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-005');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker Domain and UserProfile resources', () => {
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::UserProfile')).toBe(true);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Domain VPC-only Mode Tests', () => {
    it('should flag Domain without VPC-only mode', () => {
      const domain = createDomainResource({ 
        AppNetworkAccessType: 'PublicInternetOnly',
        LogicalId: 'PublicDomain'
      });
      
      const result = rule.evaluate(domain, stackName);
      
      expect(result).not.toBeNull();
      expect(result?.resourceName).toBe('PublicDomain');
      expect(result?.issue).toContain('SageMaker Domain is not configured for VPC-only mode');
      expect(result?.fix).toBe('Set AppNetworkAccessType to \'VpcOnly\' for enhanced security.');
    });

    it('should not flag Domain with VPC-only mode', () => {
      const domain = createDomainResource({ AppNetworkAccessType: 'VpcOnly' });
      
      const result = rule.evaluate(domain, stackName);
      
      expect(result).toBeNull();
    });
  });

  describe('UserProfile Security Group Tests', () => {
    it('should flag UserProfile without security groups', () => {
      const userProfile = createUserProfileResource({ 
        LogicalId: 'NoSecurityGroups',
        SecurityGroups: undefined
      });
      delete userProfile.Properties.UserSettings.SecurityGroups;
      
      const result = rule.evaluate(userProfile, stackName, [userProfile]);
      
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('UserProfile does not have dedicated security groups configured');
      expect(result?.fix).toBe('Configure distinct security groups for each user profile.');
    });

    it('should flag UserProfiles sharing security groups', () => {
      const sharedSG = 'sg-shared123';
      const userProfile1 = createUserProfileResource({ 
        LogicalId: 'UserProfile1',
        SecurityGroups: [sharedSG]
      });
      const userProfile2 = createUserProfileResource({ 
        LogicalId: 'UserProfile2',
        SecurityGroups: [sharedSG]
      });
      const allResources = [userProfile1, userProfile2];
      
      const result1 = rule.evaluate(userProfile1, stackName, allResources);
      
      expect(result1).not.toBeNull();
      expect(result1?.issue).toContain('UserProfile shares security groups with other user profiles');
      expect(result1?.fix).toBe('Use distinct security groups for each user profile.');
    });

    it('should not flag UserProfiles with distinct security groups', () => {
      const userProfile1 = createUserProfileResource({ 
        SecurityGroups: ['sg-unique1']
      });
      const userProfile2 = createUserProfileResource({ 
        SecurityGroups: ['sg-unique2']
      });
      const allResources = [userProfile1, userProfile2];
      
      const result1 = rule.evaluate(userProfile1, stackName, allResources);
      const result2 = rule.evaluate(userProfile2, stackName, allResources);
      
      expect(result1).toBeNull();
      expect(result2).toBeNull();
    });
  });
});