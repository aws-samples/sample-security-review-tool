import { describe, it, expect } from 'vitest';
import { SageMaker004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sagemaker/004-studio-experience.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SageMaker004Rule', () => {
  const rule = new SageMaker004Rule();
  const stackName = 'test-stack';

  // Helper function to create SageMaker Domain test resources
  function createDomainResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::SageMaker::Domain',
      Properties: {
        DomainName: 'TestDomain',
        AuthMode: 'IAM',
        VpcId: 'vpc-12345',
        SubnetIds: ['subnet-12345', 'subnet-67890'],
        ...props
      },
      LogicalId: props.LogicalId || 'TestDomain'
    };
  }

  describe('Basic Rule Properties', () => {
    it('should have the correct rule ID', () => {
      expect(rule.id).toBe('SAGEMAKER-004');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to SageMaker Domain resources only', () => {
      expect(rule.appliesTo('AWS::SageMaker::Domain')).toBe(true);
      expect(rule.appliesTo('AWS::SageMaker::NotebookInstance')).toBe(false);
      expect(rule.appliesTo('AWS::EC2::Instance')).toBe(false);
    });
  });

  describe('Domain Configuration Tests', () => {
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
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.fix).toContain('Configure DefaultUserSettings with StudioWebPortal set to \'ENABLED\'');
    });

    it('should flag domain with missing DefaultUserSettings', () => {
      // Arrange
      const domain = createDomainResource();
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.fix).toContain('Add DefaultUserSettings property');
    });

    it('should flag domain with StudioWebPortal set to DISABLED', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          StudioWebPortal: 'DISABLED'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.issue).toContain('StudioWebPortal is explicitly set to \'DISABLED\'');
    });

    it('should flag domain with DefaultLandingUri starting with app:JupyterServer::', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          DefaultLandingUri: 'app:JupyterServer::Jupyter'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.issue).toContain('DefaultLandingUri is set to \'app:JupyterServer::Jupyter\'');
    });

    it('should flag domain with neither StudioWebPortal nor DefaultLandingUri specified', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {}
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.issue).toContain('Neither StudioWebPortal nor DefaultLandingUri are specified');
    });

    it('should flag domain with StudioWebPortal=ENABLED but DefaultLandingUri not set to studio::', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          StudioWebPortal: 'ENABLED',
          DefaultLandingUri: 'something-else'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.issue).toContain('StudioWebPortal is \'ENABLED\' but DefaultLandingUri is not set to \'studio::\'');
    });

    it('should flag domain with DefaultLandingUri=studio:: but StudioWebPortal not specified', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          DefaultLandingUri: 'studio::'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.issue).toContain('DefaultLandingUri is set to \'studio::\' but StudioWebPortal is not specified');
    });

    it('should not flag domain with correct configuration (StudioWebPortal=ENABLED and DefaultLandingUri=studio::)', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          StudioWebPortal: 'ENABLED',
          DefaultLandingUri: 'studio::'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Intrinsic Function Tests', () => {
    it('should flag domain with StudioWebPortal as CloudFormation intrinsic function', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          StudioWebPortal: { Ref: 'StudioWebPortalParameter' },
          DefaultLandingUri: 'studio::'
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.fix).toContain('Set StudioWebPortal to an explicit string value');
    });

    it('should flag domain with DefaultLandingUri as CloudFormation intrinsic function', () => {
      // Arrange
      const domain = createDomainResource({
        DefaultUserSettings: {
          StudioWebPortal: 'ENABLED',
          DefaultLandingUri: { Ref: 'DefaultLandingUriParameter' }
        }
      });
      
      // Act
      const result = rule.evaluate(domain, stackName);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SageMaker::Domain');
      expect(result?.resourceName).toBe('TestDomain');
      expect(result?.issue).toContain('SageMaker Domain is configured to use Studio Classic');
      expect(result?.fix).toContain('Set DefaultLandingUri to an explicit string value');
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
