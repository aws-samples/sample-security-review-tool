import { describe, it, expect, beforeEach } from 'vitest';
import { CodePipeline002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/codepipeline/002-secrets-manager-usage.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CODEPIPELINE-002: Use AWS Secrets Manager for credentials in CodePipeline', () => {
  let rule: CodePipeline002Rule;

  beforeEach(() => {
    rule = new CodePipeline002Rule();
  });

  it('should flag pipeline with hardcoded credentials', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        Stages: [{
          Name: 'Source',
          Actions: [{
            Name: 'SourceAction',
            ActionTypeId: {
              Category: 'Source',
              Owner: 'ThirdParty',
              Provider: 'GitHub'
            },
            Configuration: {
              OAuthToken: 'ghp_hardcoded_token_123456'
            }
          }]
        }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('CodePipeline contains hardcoded credentials');
    expect(result?.fix).toContain('{{resolve:secretsmanager:');
  });

  it('should pass pipeline with Secrets Manager reference', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        Stages: [{
          Name: 'Source',
          Actions: [{
            Name: 'SourceAction',
            ActionTypeId: {
              Category: 'Source',
              Owner: 'ThirdParty',
              Provider: 'GitHub'
            },
            Configuration: {
              OAuthToken: '{{resolve:secretsmanager:github-token:SecretString:token}}'
            }
          }]
        }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).toBeNull();
  });

  it('should pass pipeline without credential fields', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        Stages: [{
          Name: 'Build',
          Actions: [{
            Name: 'BuildAction',
            ActionTypeId: {
              Category: 'Build',
              Owner: 'AWS',
              Provider: 'CodeBuild'
            },
            Configuration: {
              ProjectName: 'MyProject'
            }
          }]
        }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).toBeNull();
  });
});