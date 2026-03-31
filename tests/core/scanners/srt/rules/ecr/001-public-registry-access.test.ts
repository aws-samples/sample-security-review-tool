import { describe, it, expect } from 'vitest';
import { ECR001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecr/001-public-registry-access.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECR001Rule', () => {
  const rule = new ECR001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a public repository is created without intentional tags', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::PublicRepository',
        Properties: {
          RepositoryName: 'my-public-repo'
        },
        LogicalId: 'MyPublicRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ECR::PublicRepository');
      expect(result?.resourceName).toBe('MyPublicRepo');
      expect(result?.issue).toContain('ECR repository is configured as public');
    });

    it('should not return a finding if a public repository has an intentional public tag', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::PublicRepository',
        Properties: {
          RepositoryName: 'my-public-repo',
          Tags: [
            {
              Key: 'Public',
              Value: 'Intentional'
            }
          ]
        },
        LogicalId: 'MyPublicRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a public repository has a Purpose=Public tag', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::PublicRepository',
        Properties: {
          RepositoryName: 'my-public-repo',
          Tags: [
            {
              Key: 'Purpose',
              Value: 'Public'
            }
          ]
        },
        LogicalId: 'MyPublicRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a private repository has a policy allowing public access', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ecr:GetDownloadUrlForLayer'
              }
            ]
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ECR::Repository');
      expect(result?.resourceName).toBe('MyPrivateRepo');
      expect(result?.issue).toContain('overly permissive repository policy');
    });

    it('should not return a finding if a private repository has a policy with conditions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ecr:GetDownloadUrlForLayer',
                Condition: {
                  StringEquals: {
                    'aws:SourceVpc': 'vpc-12345'
                  }
                }
              }
            ]
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a private repository has a policy with specific principals', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: {
                  AWS: 'arn:aws:iam::123456789012:role/MyRole'
                },
                Action: 'ecr:GetDownloadUrlForLayer'
              }
            ]
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle string JSON policy text', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: JSON.stringify({
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ecr:GetDownloadUrlForLayer'
              }
            ]
          })
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::ECR::Repository');
      expect(result?.resourceName).toBe('MyPrivateRepo');
      expect(result?.issue).toContain('overly permissive repository policy');
    });

    it('should return null for non-ECR resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'MyBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle invalid JSON policy text gracefully', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: 'not-valid-json'
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in tags for public repositories', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::PublicRepository',
        Properties: {
          RepositoryName: 'my-public-repo',
          Tags: [
            {
              Key: { 'Fn::Sub': 'Public' },
              Value: { 'Fn::Sub': 'Intentional' }
            }
          ]
        },
        LogicalId: 'MyPublicRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle CDK-generated token values in tags', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::PublicRepository',
        Properties: {
          RepositoryName: 'my-public-repo',
          Tags: {
            'Fn::GetAtt': ['SomeResource', 'Tags']
          }
        },
        LogicalId: 'MyPublicRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Since we can't determine for sure if the tags include intentional public access indicators,
      // we should give the benefit of the doubt if the tags string includes relevant keywords
      expect(result).not.toBeNull();
    });

    it('should handle intrinsic functions in repository policy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            'Fn::Sub': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:GetDownloadUrlForLayer"}]}'
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('potentially overly permissive repository policy defined with intrinsic functions');
    });

    it('should handle intrinsic functions in repository policy statement principal', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { 'Fn::Sub': '*' },
                Action: 'ecr:GetDownloadUrlForLayer'
              }
            ]
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('potentially overly permissive repository policy with intrinsic functions');
    });

    it('should handle intrinsic functions in repository policy statement condition', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::ECR::Repository',
        Properties: {
          RepositoryName: 'my-private-repo',
          RepositoryPolicyText: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: '*',
                Action: 'ecr:GetDownloadUrlForLayer',
                Condition: { 'Fn::GetAtt': ['SomeResource', 'Condition'] }
              }
            ]
          }
        },
        LogicalId: 'MyPrivateRepo'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
