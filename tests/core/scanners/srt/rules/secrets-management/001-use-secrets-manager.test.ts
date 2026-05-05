import { describe, it, expect } from 'vitest';
import { Sec001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/secrets-management/001-use-secrets-manager.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Sec001Rule', () => {
  const rule = new Sec001Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::Lambda::Function', () => {
      it('should return a finding if a Lambda function has sensitive environment variables not using Secrets Manager', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'TestFunction',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {
              S3Bucket: 'my-bucket',
              S3Key: 'my-key'
            },
            Runtime: 'nodejs14.x',
            Environment: {
              Variables: {
                DB_PASSWORD: 'plaintext-password',
                API_KEY: 'plaintext-key',
                SECRET_TOKEN: 'plaintext-token'
              }
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::Lambda::Function');
        expect(result?.resourceName).toBe('TestFunction');
        expect(result?.issue).toContain('Sensitive data not stored in AWS Secrets Manager');
      });

      it('should not return a finding if a Lambda function has sensitive environment variables using Secrets Manager', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'TestFunction',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {
              S3Bucket: 'my-bucket',
              S3Key: 'my-key'
            },
            Runtime: 'nodejs14.x',
            Environment: {
              Variables: {
                DB_PASSWORD: '{{resolve:secretsmanager:MySecret:SecretString:password}}',
                API_KEY: '{{resolve:secretsmanager:MySecret:SecretString:api_key}}',
                SECRET_TOKEN: '{{resolve:secretsmanager:MySecret:SecretString:token}}'
              }
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a Lambda function has no sensitive environment variables', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'TestFunction',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {
              S3Bucket: 'my-bucket',
              S3Key: 'my-key'
            },
            Runtime: 'nodejs14.x',
            Environment: {
              Variables: {
                REGION: 'us-west-2',
                STAGE: 'prod',
                LOG_LEVEL: 'info'
              }
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a Lambda function has no environment variables', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'TestFunction',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {
              S3Bucket: 'my-bucket',
              S3Key: 'my-key'
            },
            Runtime: 'nodejs14.x'
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('AWS::ECS::TaskDefinition', () => {
      it('should return null for an ECS task definition as it is handled by ECS-002 rule', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            Family: 'TestTask',
            ContainerDefinitions: [
              {
                Name: 'TestContainer',
                Image: 'test-image',
                Environment: [
                  {
                    Name: 'DB_PASSWORD',
                    Value: 'plaintext-password'
                  },
                  {
                    Name: 'API_KEY',
                    Value: 'plaintext-key'
                  }
                ]
              }
            ]
          },
          LogicalId: 'TestTask'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if an ECS task definition has sensitive environment variables using Secrets Manager', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            Family: 'TestTask',
            ContainerDefinitions: [
              {
                Name: 'TestContainer',
                Image: 'test-image',
                Environment: [
                  {
                    Name: 'DB_PASSWORD',
                    Value: '{{resolve:secretsmanager:MySecret:SecretString:password}}'
                  },
                  {
                    Name: 'API_KEY',
                    Value: '{{resolve:secretsmanager:MySecret:SecretString:api_key}}'
                  }
                ]
              }
            ]
          },
          LogicalId: 'TestTask'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if an ECS task definition has no sensitive environment variables', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            Family: 'TestTask',
            ContainerDefinitions: [
              {
                Name: 'TestContainer',
                Image: 'test-image',
                Environment: [
                  {
                    Name: 'REGION',
                    Value: 'us-west-2'
                  },
                  {
                    Name: 'STAGE',
                    Value: 'prod'
                  }
                ]
              }
            ]
          },
          LogicalId: 'TestTask'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if an ECS task definition has no environment variables', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            Family: 'TestTask',
            ContainerDefinitions: [
              {
                Name: 'TestContainer',
                Image: 'test-image'
              }
            ]
          },
          LogicalId: 'TestTask'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });
    });

    it('should return null for unsupported resource types', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
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
