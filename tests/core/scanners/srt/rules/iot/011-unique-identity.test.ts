import { describe, it, expect } from 'vitest';
import IoT011Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/011-unique-identity.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT011Rule', () => {
  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Thing without unique identity attributes', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            // Missing unique identity attributes
            location: 'warehouse'
          }
        }
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing unique identity attributes');
  });

  it('should flag IoT Thing without certificate association', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            serialNumber: '12345',
            deviceId: 'device-001'
          }
        }
      }
    };

    // No certificate attachment in allResources
    const allResources: CloudFormationResource[] = [
      resource
    ];

    const result = IoT011Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('no X.509 certificate association');
  });

  it('should not flag properly configured IoT Thing with certificate association', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            serialNumber: '12345',
            deviceId: 'device-001'
          }
        }
      }
    };

    // Include certificate attachment in allResources
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::IoT::ThingPrincipalAttachment',
        LogicalId: 'TestThingCertificateAttachment',
        Properties: {
          ThingName: 'test-thing',
          Principal: 'arn:aws:iot:us-east-1:123456789012:cert/abcdef1234567890'
        }
      }
    ];

    const result = IoT011Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  it('should flag IoT Certificate that is not active', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Certificate',
      LogicalId: 'TestCertificate',
      Properties: {
        Status: 'INACTIVE',
        CertificatePem: '-----BEGIN CERTIFICATE-----\nMIICdzCCAV+gAwIBAgIJAMsf+RzRaB6...'
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('certificate not properly configured');
  });

  it('should flag IoT Certificate without CSR or PEM', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Certificate',
      LogicalId: 'TestCertificate',
      Properties: {
        Status: 'ACTIVE'
        // Missing both CertificateSigningRequest and CertificatePem
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('certificate not properly configured');
  });

  it('should not flag properly configured IoT Certificate', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Certificate',
      LogicalId: 'TestCertificate',
      Properties: {
        Status: 'ACTIVE',
        CertificatePem: '-----BEGIN CERTIFICATE-----\nMIICdzCCAV+gAwIBAgIJAMsf+RzRaB6...'
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Policy that does not enforce unique identity', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Policy',
      LogicalId: 'TestPolicy',
      Properties: {
        PolicyName: 'test-policy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'iot:Connect',
              Resource: '*'
            }
            // Missing unique identity enforcement
          ]
        }
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('policy does not enforce unique identity');
  });

  it('should not flag IoT Policy that enforces unique identity', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Policy',
      LogicalId: 'TestPolicy',
      Properties: {
        PolicyName: 'test-policy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'iot:Connect',
              Resource: 'arn:aws:iot:us-east-1:123456789012:client/${iot:ClientId}'
            },
            {
              Effect: 'Allow',
              Action: 'iot:Publish',
              Resource: 'arn:aws:iot:us-east-1:123456789012:topic/${iot:Connection.Thing.ThingName}/*'
            }
          ]
        }
      }
    };

    const result = IoT011Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});
