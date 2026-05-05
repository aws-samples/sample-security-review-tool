import { describe, it, expect } from 'vitest';
import MSK004Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/004-iam-authentication.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK004Rule - IAM Authentication', () => {
  const rule = MSK004Rule;

  it('should pass when IAM authentication is enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Iam: {
              Enabled: true
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when ClientAuthentication is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster is not configured with IAM authentication');
    expect(result?.fix).toContain('Add ClientAuthentication.Sasl.Iam.Enabled: true');
  });

  it('should fail when IAM authentication is explicitly disabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Iam: {
              Enabled: false
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster is not configured with IAM authentication');
    expect(result?.fix).toContain('Set ClientAuthentication.Sasl.Iam.Enabled to true');
  });

  it('should fail when Sasl is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {}
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster is not configured with IAM authentication');
  });

  it('should fail when Iam is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {}
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster is not configured with IAM authentication');
  });

  it('should ignore non-MSK resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestS3Bucket',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass with complex ClientAuthentication configuration including IAM', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Iam: {
              Enabled: true
            },
            Scram: {
              Enabled: false
            }
          },
          Tls: {
            Enabled: false
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});