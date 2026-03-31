import { describe, test, expect, beforeEach } from 'vitest';
import { Ecs002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/002-sensitive-parameters.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Ecs002Rule', () => {
  let rule: Ecs002Rule;
  const stackName = 'TestStack';

  beforeEach(() => {
    rule = new Ecs002Rule();
  });

  function createTemplate(resourceId: string, resource: Resource): Template {
    return {
      Resources: {
        [resourceId]: resource
      }
    };
  }

  describe('appliesTo', () => {
    test('should return true for AWS::ECS::TaskDefinition', () => {
      expect(rule.appliesTo('AWS::ECS::TaskDefinition')).toBe(true);
    });

    test('should return false for other resource types', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    test('should return null for non-ECS TaskDefinition resources', () => {
      const resource: Resource = {
        Type: 'AWS::S3::Bucket',
        Properties: {}
      };
      const template = createTemplate('TestBucket', resource);

      const result = rule.evaluateResource(stackName, template, resource);
      expect(result).toBeNull();
    });

    test('should return null when no container definitions exist', () => {
      const resource: Resource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {}
      };
      const template = createTemplate('TestTaskDefinition', resource);

      const result = rule.evaluateResource(stackName, template, resource);
      expect(result).toBeNull();
    });

    test('should return null for empty ContainerDefinitions array', () => {
      const resource: Resource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          ContainerDefinitions: []
        }
      };
      const template = createTemplate('TestTaskDefinition', resource);

      const result = rule.evaluateResource(stackName, template, resource);
      expect(result).toBeNull();
    });

    // Environment variable tests
    describe('environment variables', () => {
      test('should detect sensitive names like DATABASE_PASSWORD', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'DATABASE_PASSWORD', Value: 'value' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('DATABASE_PASSWORD');
      });

      test('should detect API_KEY as sensitive', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'API_KEY', Value: 'abcdef1234567890abcdef1234567890' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('API_KEY');
      });

      test('should detect SECRET_TOKEN as sensitive', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'SECRET_TOKEN', Value: 'value' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('SECRET_TOKEN');
      });

      test('should detect connection strings with credentials in value', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'DB_URL', Value: 'mongodb://user:pass@host:27017/db' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
      });

      test('should return null when environment is empty', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: []
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should return null for non-sensitive environment variables', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'APP_NAME', Value: 'myapp' },
                  { Name: 'PORT', Value: '3000' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });
    });

    // Safe environment variable tests
    describe('safe environment variables', () => {
      test('should not flag AWS_NODEJS_CONNECTION_REUSE_ENABLED', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_NODEJS_CONNECTION_REUSE_ENABLED', Value: '1' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag AWS_MAX_ATTEMPTS', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_MAX_ATTEMPTS', Value: '3' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag AWS_RETRY_MODE', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_RETRY_MODE', Value: 'adaptive' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag AWS_REGION', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_REGION', Value: 'us-east-1' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag AWS_DEFAULT_REGION', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_DEFAULT_REGION', Value: 'us-west-2' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag NODE_ENV', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'NODE_ENV', Value: 'production' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag LOG_LEVEL', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'LOG_LEVEL', Value: 'debug' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag CONNECTION_TIMEOUT', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'CONNECTION_TIMEOUT', Value: '30000' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag CONNECTION_POOL_SIZE', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'CONNECTION_POOL_SIZE', Value: '10' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should not flag multiple safe env vars together', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_NODEJS_CONNECTION_REUSE_ENABLED', Value: '1' },
                  { Name: 'AWS_REGION', Value: 'us-west-2' },
                  { Name: 'NODE_ENV', Value: 'production' },
                  { Name: 'LOG_LEVEL', Value: 'info' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should flag API_KEY but not AWS_REGION in same container', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'AWS_REGION', Value: 'us-east-1' },
                  { Name: 'API_KEY', Value: 'sk-1234567890abcdef1234567890abcdef' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('API_KEY');
        expect(result?.issue).not.toContain('AWS_REGION');
      });

      test('should still flag CONNECTION_STRING as sensitive', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'CONNECTION_STRING', Value: 'mongodb://user:pass@host:27017/db' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
      });

      test('should handle case-insensitive safe env var matching', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  { Name: 'aws_region', Value: 'us-east-1' },
                  { Name: 'Node_Env', Value: 'production' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });
    });

    // Secrets tests
    describe('secrets', () => {
      test('should return null for valid Secrets Manager reference', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  {
                    Name: 'DATABASE_PASSWORD',
                    ValueFrom: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:database-password-123abc'
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should return null for valid SSM reference', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  {
                    Name: 'DATABASE_PASSWORD',
                    ValueFrom: 'arn:aws:ssm:us-west-2:123456789012:parameter/myapp/password'
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should detect secrets without ValueFrom property', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  { Name: 'DATABASE_PASSWORD' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('without ValueFrom');
      });

      test('should detect secrets with invalid ValueFrom reference', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  { Name: 'DATABASE_PASSWORD', ValueFrom: 'invalid-reference' }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('may not reference Secrets Manager or SSM');
      });

      test('should return null for valid intrinsic function referencing secretsmanager', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  {
                    Name: 'DATABASE_PASSWORD',
                    ValueFrom: {
                      'Fn::Join': [
                        '',
                        [
                          'arn:',
                          { Ref: 'AWS::Partition' },
                          ':secretsmanager:',
                          { Ref: 'AWS::Region' },
                          ':',
                          { Ref: 'AWS::AccountId' },
                          ':secret:',
                          { Ref: 'DatabaseSecret' }
                        ]
                      ]
                    }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should return null for CDK SecretString pattern', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  {
                    Name: 'DATABASE_PASSWORD',
                    ValueFrom: { 'Fn::GetAtt': ['DatabaseSecretAttachment', 'SecretString'] }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should detect invalid intrinsic function in secrets', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Secrets: [
                  {
                    Name: 'DATABASE_PASSWORD',
                    ValueFrom: {
                      'Fn::Join': ['', ['invalid:', { Ref: 'SomeResource' }, ':reference']]
                    }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('intrinsic may not reference');
      });
    });

    // Intrinsic function tests
    describe('intrinsic functions in environment variables', () => {
      test('should detect Fn::Sub with password variable', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  {
                    Name: 'CONNECTION_STRING',
                    Value: { 'Fn::Sub': 'postgresql://${DbUser}:${DbPassword}@${DbHost}:5432/${DbName}' }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
      });

      test('should detect Fn::Join with password pattern', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  {
                    Name: 'DB_CONN',
                    Value: {
                      'Fn::Join': [
                        '',
                        [
                          'mongodb://',
                          { Ref: 'DbUsername' },
                          ':',
                          { Ref: 'DbPassword' },
                          '@',
                          { 'Fn::GetAtt': ['MongoDBInstance', 'Endpoint.Address'] }
                        ]
                      ]
                    }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
      });

      test('should return null for Fn::GetAtt to database endpoint only', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  {
                    Name: 'DATABASE_URL',
                    Value: { 'Fn::GetAtt': ['MyDatabase', 'Endpoint.Address'] }
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).toBeNull();
      });

      test('should detect sensitive intrinsic function names', () => {
        const resource: Resource = {
          Type: 'AWS::ECS::TaskDefinition',
          Properties: {
            ContainerDefinitions: [
              {
                Name: 'AppContainer',
                Environment: [
                  {
                    Name: {
                      'Fn::Join': ['_', ['DATABASE', { Ref: 'Environment' }, 'PASSWORD']]
                    },
                    Value: 'someValue'
                  }
                ]
              }
            ]
          }
        };
        const template = createTemplate('TaskDef', resource);

        const result = rule.evaluateResource(stackName, template, resource);
        expect(result).not.toBeNull();
      });
    });
  });

  describe('evaluate (legacy)', () => {
    test('should return null (stub implementation)', () => {
      const result = rule.evaluate({
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {},
        LogicalId: 'Test'
      }, stackName);
      expect(result).toBeNull();
    });
  });

  describe('rule properties', () => {
    test('should have correct id', () => {
      expect(rule.id).toBe('ECS-002');
    });

    test('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    test('should apply to ECS TaskDefinition', () => {
      expect(rule.applicableResourceTypes).toContain('AWS::ECS::TaskDefinition');
    });
  });
});
