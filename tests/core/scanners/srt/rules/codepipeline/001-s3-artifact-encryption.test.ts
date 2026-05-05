import { describe, it, expect, beforeEach } from 'vitest';
import { CodePipeline001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/codepipeline/001-s3-artifact-encryption.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CODEPIPELINE-001: Use secure S3 artifact encryption in CodePipeline', () => {
  let rule: CodePipeline001Rule;

  beforeEach(() => {
    rule = new CodePipeline001Rule();
  });

  it('should flag pipeline without encryption key', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        ArtifactStore: {
          Type: 'S3',
          Location: 'my-bucket'
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('CodePipeline does not use customer-managed KMS key');
    expect(result?.fix).toContain('"Type": "KMS"');
  });

  it('should flag pipeline with AWS managed key', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        ArtifactStore: {
          Type: 'S3',
          Location: 'my-bucket',
          EncryptionKey: {
            Type: 'KMS',
            Id: 'alias/aws/s3'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('CodePipeline does not use customer-managed KMS key');
  });

  it('should pass pipeline with customer-managed KMS key', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::CodePipeline::Pipeline',
      LogicalId: 'TestPipeline',
      Properties: {
        ArtifactStore: {
          Type: 'S3',
          Location: 'my-bucket',
          EncryptionKey: {
            Type: 'KMS',
            Id: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).toBeNull();
  });
});