import { describe, it, expect } from 'vitest';
import MSK005Rule from '../../../../../../src/assess/scanning/security-matrix/rules/msk/005-acl-authorization.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('MSK005Rule - ACL Authorization', () => {
  const rule = MSK005Rule;

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

  it('should pass when SCRAM authentication is enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Scram: {
              Enabled: true
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when both IAM and SCRAM are enabled', () => {
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
      Properties: {
        ClusterName: 'test-cluster'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.issue).toContain('MSK cluster does not have proper authentication configured for ACL authorization');
    expect(result?.fix).toContain('Add ClientAuthentication.Sasl.Iam.Enabled: true');
  });

  it('should fail when Sasl is missing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Tls: {
            Enabled: true
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Add ClientAuthentication.Sasl.Iam.Enabled: true');
  });

  it('should fail when both IAM and SCRAM are disabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Iam: {
              Enabled: false
            },
            Scram: {
              Enabled: false
            }
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toContain('Set ClientAuthentication.Sasl.Iam.Enabled to true');
  });

  it('should fail when authentication methods are not explicitly enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::MSK::Cluster',
      LogicalId: 'TestMSKCluster',
      Properties: {
        ClientAuthentication: {
          Sasl: {
            Iam: {},
            Scram: {}
          }
        }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.priority).toBe('HIGH');
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
});