import { describe, it, expect } from 'vitest';
import { KMS002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/kms/002-cmk-least-privilege.cf.js';

describe('KMS-002: Restrict KMS key policies to least-privilege principles', () => {
  const rule = new KMS002Rule();

  describe('wildcard actions', () => {
    it('should flag kms:* with non-root principal', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/TestRole' },
              Action: 'kms:*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('kms:*');
      expect(result?.fix).toContain('encryption-only access');
    });

    it('should flag other dangerous wildcards like kms:Encrypt*', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/TestRole' },
              Action: 'kms:Encrypt*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('kms:Encrypt*');
    });

    it('should allow kms:GenerateDataKey* (standard AWS pattern)', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/TestRole' },
              Action: ['kms:Encrypt', 'kms:GenerateDataKey*']
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should allow kms:ReEncrypt* (standard AWS pattern)', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/TestRole' },
              Action: ['kms:Encrypt', 'kms:ReEncrypt*']
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should allow kms:GenerateDataKeyPair* (standard AWS pattern)', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/TestRole' },
              Action: 'kms:GenerateDataKeyPair*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });
  });

  describe('CDK root account pattern', () => {
    it('should allow root account with kms:* (CDK default)', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:root' },
              Action: 'kms:*',
              Resource: '*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should allow root account with kms:* in array format', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: ['arn:aws:iam::123456789012:root'] },
              Action: 'kms:*',
              Resource: '*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should flag root account with other dangerous wildcards', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:root' },
              Action: 'kms:Encrypt*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
    });
  });

  describe('wildcard principals', () => {
    it('should flag * principal', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: '*',
              Action: 'kms:Encrypt'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('wildcard principal "*"');
    });

    it('should flag wildcard account in ARN', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::*:root' },
              Action: 'kms:Encrypt'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('arn:aws:iam::*:root');
    });

    it('should flag wildcard in principal array', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: ['arn:aws:iam::123456789012:role/Good', 'arn:aws:iam::*:root'] },
              Action: 'kms:Encrypt'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).not.toBeNull();
    });
  });

  describe('compliant policies', () => {
    it('should pass specific actions with specific principal', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/EncryptRole' },
              Action: 'kms:Encrypt'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should pass service principal with broad actions', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'macie.amazonaws.com' },
              Action: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey*', 'kms:ReEncrypt*', 'kms:DescribeKey']
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should pass CDK Macie key pattern with multiple statements', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [
              {
                Action: 'kms:*',
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::123456789012:root' },
                Resource: '*'
              },
              {
                Action: ['kms:Decrypt', 'kms:DescribeKey', 'kms:Encrypt', 'kms:GenerateDataKey*', 'kms:ReEncrypt*'],
                Condition: { StringEquals: { 'aws:SourceAccount': '123456789012' } },
                Effect: 'Allow',
                Principal: { Service: 'macie.amazonaws.com' },
                Resource: '*'
              },
              {
                Action: ['kms:Decrypt', 'kms:DescribeKey', 'kms:Encrypt', 'kms:GenerateDataKey*', 'kms:ReEncrypt*'],
                Effect: 'Allow',
                Principal: { AWS: 'arn:aws:iam::123456789012:root' },
                Resource: '*'
              }
            ]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { MacieResultsKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should pass encrypt+decrypt for same IAM role (no separation of duties enforcement)', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::123456789012:role/AppRole' },
              Action: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey*']
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should ignore non-KMS resources', () => {
      const resource = {
        Type: 'AWS::S3::Bucket',
        Properties: {}
      };

      const result = rule.evaluateResource('TestStack', { Resources: {} }, resource);
      expect(result).toBeNull();
    });

    it('should pass when no KeyPolicy defined', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          EnableKeyRotation: true
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });

    it('should ignore Deny statements', () => {
      const resource = {
        Type: 'AWS::KMS::Key',
        Properties: {
          KeyPolicy: {
            Statement: [{
              Effect: 'Deny',
              Principal: '*',
              Action: 'kms:*'
            }]
          }
        }
      };

      const result = rule.evaluateResource('TestStack', { Resources: { TestKey: resource } }, resource);
      expect(result).toBeNull();
    });
  });

  describe('rule properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('KMS-002');
      expect(rule.priority).toBe('HIGH');
      expect(rule.appliesTo('AWS::KMS::Key')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });
});
