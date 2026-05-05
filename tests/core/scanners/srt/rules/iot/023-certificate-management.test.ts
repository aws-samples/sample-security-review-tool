import { describe, it, expect } from 'vitest';
import { IoT023Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/023-certificate-management.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT023Rule - Ensure IoT device certificates are managed', () => {
  const rule = new IoT023Rule();
  const stackName = 'test-stack';

  describe('Basic Rule Properties', () => {
    it('should have correct rule properties', () => {
      expect(rule.id).toBe('IOT-023');
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to correct resource types', () => {
      expect(rule.appliesTo('AWS::IoT::Certificate')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Thing')).toBe(true);
      expect(rule.appliesTo('AWS::IoT::Policy')).toBe(true);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('Certificate Evaluation', () => {
    it('should pass when certificate has proper status and rotation', () => {
      const certificate = {
        Type: 'AWS::IoT::Certificate',
        LogicalId: 'TestCertificate',
        Properties: {
          Status: 'ACTIVE',
          CertificateSigningRequest: 'test-csr'
        }
      };
      const rotationLambda = {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'RotationFunction',
        Properties: {
          Code: { ZipFile: 'certificate rotate renewal code' }
        }
      };

      const allResources = [certificate, rotationLambda];
      const result = rule.evaluate(certificate, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when certificate status is pending', () => {
      const certificate = {
        Type: 'AWS::IoT::Certificate',
        LogicalId: 'TestCertificate',
        Properties: {
          Status: 'PENDING_ACTIVATION',
          CertificateSigningRequest: 'test-csr'
        }
      };

      const result = rule.evaluate(certificate, stackName, [certificate]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('certificate status not properly managed');
    });

    it('should fail when no rotation mechanism exists', () => {
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
      expect(result?.issue).toContain('no certificate rotation mechanism configured');
    });
  });

  describe('Thing Evaluation', () => {
    it('should pass when thing has associated certificates', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };
      const attachment = {
        Type: 'AWS::IoT::ThingPrincipalAttachment',
        LogicalId: 'Attachment',
        Properties: {
          ThingName: { Ref: 'TestThing' },
          Principal: 'cert-arn'
        }
      };

      const allResources = [thing, attachment];
      const result = rule.evaluate(thing, stackName, allResources);
      expect(result).toBeNull();
    });

    it('should fail when thing has no certificates', () => {
      const thing = {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: { ThingName: 'test-thing' }
      };

      const result = rule.evaluate(thing, stackName, [thing]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('no certificates associated with thing');
    });
  });

  describe('Policy Evaluation', () => {
    it('should pass when policy has proper conditions', () => {
      const policy = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 'iot:CreateCertificate',
              Resource: '*',
              Condition: { StringEquals: { 'iot:ThingName': 'test-thing' } }
            }]
          }
        }
      };

      const result = rule.evaluate(policy, stackName, [policy]);
      expect(result).toBeNull();
    });

    it('should fail when certificate management policy lacks conditions', () => {
      const policy = {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 'iot:CreateCertificate',
              Resource: '*'
            }]
          }
        }
      };

      const result = rule.evaluate(policy, stackName, [policy]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('certificate management policy lacks conditions');
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