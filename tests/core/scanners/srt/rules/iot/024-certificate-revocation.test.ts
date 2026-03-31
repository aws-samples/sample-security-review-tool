import { describe, it, expect } from 'vitest';
import { IoT024Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/024-certificate-revocation.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT024Rule - Use certificate revocation lists', () => {
  const rule = new IoT024Rule();
  const stackName = 'test-stack';

  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-024');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::CACertificate')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Certificate')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Policy')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('CA Certificate Evaluation', () => {
    it('should pass when CA certificate has proper configuration', () => {
      const caCertificate = {
        Type: 'AWS::IoT::CACertificate',
        LogicalId: 'TestCACert',
        Properties: {
          CACertificatePem: 'test-ca-cert',
          Status: 'ACTIVE',
          RegistrationConfig: {
            TemplateBody: 'template',
            RoleArn: 'role-arn'
          }
        }
      };
      const revocationLambda = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'RevocationFunction',
        Properties: {
          Code: { ZipFile: 'revocation checking code' }
        }
      };

      const allResources = [caCertificate, revocationLambda];
      const result = rule.evaluate(caCertificate, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when CA certificate lacks registration config', () => {
      const caCertificate = {
        Type: 'AWS::IoT::CACertificate',
        LogicalId: 'TestCACert',
        Properties: {
          CACertificatePem: 'test-ca-cert',
          Status: 'ACTIVE'
        }
      };

      const result = rule.evaluate(caCertificate, stackName, [caCertificate]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no registration configuration for CA certificate');
    });

    it('should fail when no revocation checking exists', () => {
      const caCertificate = {
        Type: 'AWS::IoT::CACertificate',
        LogicalId: 'TestCACert',
        Properties: {
          CACertificatePem: 'test-ca-cert',
          Status: 'ACTIVE',
          RegistrationConfig: {
            TemplateBody: 'template',
            RoleArn: 'role-arn'
          }
        }
      };

      const result = rule.evaluate(caCertificate, stackName, [caCertificate]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no certificate revocation checking configured');
    });
  });

  describe('Certificate Evaluation', () => {
    it('should pass when CA certificate exists for revocation management', () => {
      const certificate = {
        Type: 'AWS::IoT::Certificate',
        LogicalId: 'TestCertificate',
        Properties: {
          Status: 'ACTIVE',
          CertificateSigningRequest: 'test-csr'
        }
      };
      const caCertificate = {
        Type: 'AWS::IoT::CACertificate',
        LogicalId: 'TestCACert',
        Properties: {
          CACertificatePem: 'test-ca-cert',
          Status: 'ACTIVE'
        }
      };

      const allResources = [certificate, caCertificate];
      const result = rule.evaluate(certificate, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when no CA certificate exists', () => {
      const certificate = {
        Type: 'AWS::IoT::Certificate',
        LogicalId: 'TestCertificate',
        Properties: {
          Status: 'ACTIVE',
          CertificateSigningRequest: 'test-csr'
        }
      };

      const result = rule.evaluate(certificate, stackName, [certificate]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no CA certificate for revocation management');
    });
  });

  describe('Policy Evaluation', () => {
    it('should pass when revocation policy has proper conditions', () => {
      const policy = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 'iot:UpdateCACertificate',
              Resource: '*',
              Condition: { StringEquals: { 'iot:CertificateMode': 'SNI_ONLY' } }
            }]
          }
        }
      };

      const result = rule.evaluate(policy, stackName, [policy]);
      expect(result).toBeNull();
    });

    it('should fail when revocation policy lacks conditions', () => {
      const policy = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 'iot:UpdateCACertificate',
              Resource: '*'
            }]
          }
        }
      };

      const result = rule.evaluate(policy, stackName, [policy]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('revocation policy lacks proper conditions');
    });
  });

  describe('Edge Cases', () => {
    it('should ignore non-applicable resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        LogicalId: 'TestBucket',
        Properties: { BucketName: 'my-bucket' }
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::IoT::Certificate',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});