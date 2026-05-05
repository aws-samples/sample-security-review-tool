import { describe, it, expect } from 'vitest';
import { CompLamb002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/lambda/002-secrets-manager.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CompLamb002Rule - Secrets Manager Tests', () => {
  const rule = new CompLamb002Rule();
  const stackName = 'test-stack';

  // Helper function to create Lambda test resources
  function createLambdaResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Lambda::Function',
      Properties: {
        Handler: 'index.handler',
        Runtime: 'nodejs14.x',
        Code: {
          S3Bucket: 'my-bucket',
          S3Key: 'my-key'
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestFunction'
    };
  }

  describe('Sensitive Environment Variables Detection', () => {
    it('should detect sensitive data in environment variables', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: 'abc123',
            DATABASE_PASSWORD: 'password123'
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toMatch(/Use AWS Secrets Manager or SSM Parameter Store for sensitive environment variables like '(API_KEY|DATABASE_PASSWORD)'\. Replace direct values with references like '{{resolve:secretsmanager:MySecret:SecretString:password}}' or use dynamic references with Ref or GetAtt\./);
    });

    it('should not flag functions without environment variables', () => {
      const resource = createLambdaResource({
        // No environment variables
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should not flag functions with non-sensitive environment variables', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            REGION: 'us-east-1',
            LOG_LEVEL: 'INFO'
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Secure References', () => {
    it('should accept string references to Secrets Manager', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: '{{resolve:secretsmanager:MyApiKey:SecretString:ApiKey}}'
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept string references to SSM Parameter Store secure strings', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: '{{resolve:ssm-secure:/my/secure/parameter}}'
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept Ref references to Secrets Manager', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            DATABASE_PASSWORD: { 'Ref': 'MyDatabaseSecret' }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept GetAtt references to Secrets Manager', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_SECRET: { 'Fn::GetAtt': ['MySecret', 'SecretString'] }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept Sub references to Secrets Manager', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: { 'Fn::Sub': '{{resolve:secretsmanager:${MySecret}:SecretString:ApiKey}}' }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept Join references to Secrets Manager', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: { 
              'Fn::Join': [
                '', 
                ['{{resolve:secretsmanager:', { 'Ref': 'MySecret' }, ':SecretString:ApiKey}}']
              ] 
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should accept ImportValue references to secure values', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: { 'Fn::ImportValue': 'ExportedApiSecretKey' }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Cross-Resource References', () => {
    it('should accept references to Secrets Manager resources', () => {
      const lambdaResource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: { 'Ref': 'MyApiSecret' }
          }
        },
        LogicalId: 'MyFunction'
      });
      
      const secretResource: CloudFormationResource = {
        Type: 'AWS::SecretsManager::Secret',
        Properties: {
          Name: 'my-api-secret',
          SecretString: '{"api-key": "secret-value"}'
        },
        LogicalId: 'MyApiSecret'
      };
      
      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource, secretResource]);
      expect(result).toBeNull();
    });
    
    it('should accept references to SSM Parameter resources', () => {
      const lambdaResource = createLambdaResource({
        Environment: {
          Variables: {
            API_KEY: { 'Ref': 'MyApiParameter' }
          }
        },
        LogicalId: 'MyFunction'
      });
      
      const parameterResource: CloudFormationResource = {
        Type: 'AWS::SSM::Parameter',
        Properties: {
          Name: '/my/api/key',
          Type: 'SecureString',
          Value: 'secret-value'
        },
        LogicalId: 'MyApiParameter'
      };
      
      const result = rule.evaluate(lambdaResource, stackName, [lambdaResource, parameterResource]);
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Environment section', () => {
      const resource = createLambdaResource({
        // No Environment section
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle empty Variables section', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {}
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      // Using type assertion to test a case where Properties is missing
      const resource = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should ignore non-Lambda resources', () => {
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

    it('should detect sensitive variable names with different formats', () => {
      const resource = createLambdaResource({
        Environment: {
          Variables: {
            API_PASSWORD: 'plaintext-password',
            USER_PWD: 'plaintext-password',
            ACCESS_KEY_ID: 'plaintext-key',
            PRIVATE_KEY_PATH: 'plaintext-path'
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toMatch(/Use AWS Secrets Manager or SSM Parameter Store for sensitive environment variables like '(API_PASSWORD|USER_PWD|ACCESS_KEY_ID|PRIVATE_KEY_PATH)'\. Replace direct values with references like '{{resolve:secretsmanager:MySecret:SecretString:password}}' or use dynamic references with Ref or GetAtt\./);
    });
  });
});
