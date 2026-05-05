import { describe, it, expect } from 'vitest';
import IoT005Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/005-secure-transit.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT005Rule', () => {
  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Thing without secure transit attributes', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            // Missing secure transit attributes
            location: 'warehouse'
          }
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing secure transit attributes');
  });

  it('should not flag IoT Thing with secure transit attributes', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            tlsEnabled: 'true',
            secureConnectionsOnly: 'true',
            port443Only: 'true'
          }
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Policy that does not enforce secure connections', () => {
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
            // Missing secure connection enforcement
          ]
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('policy does not enforce secure connections');
  });

  it('should not flag IoT Policy that enforces secure connections with deny statement', () => {
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
            },
            {
              Effect: 'Deny',
              Action: 'mqtt:Connect',
              Resource: '*',
              Condition: {
                Bool: {
                  'aws:SecureTransport': 'false'
                }
              }
            }
          ]
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag IoT Policy that enforces secure connections with source restrictions', () => {
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
              Resource: '*',
              Condition: {
                Bool: {
                  'aws:SecureTransport': 'true'
                },
                StringEquals: {
                  'aws:SourceVpc': 'vpc-12345678'
                }
              }
            }
          ]
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Topic Rule that does not use secure endpoints', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Actions: [
            {
              Http: {
                Url: 'http://example.com/endpoint', // Not HTTPS
                ConfirmationUrl: 'http://example.com/confirm'
              }
            }
          ]
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('topic rule does not use secure endpoints');
  });

  it('should not flag IoT Topic Rule that uses secure endpoints', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Actions: [
            {
              Http: {
                Url: 'https://example.com/endpoint', // HTTPS
                ConfirmationUrl: 'https://example.com/confirm'
              }
            }
          ]
        }
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Security Profile that does not monitor connections', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::SecurityProfile',
      LogicalId: 'TestSecurityProfile',
      Properties: {
        SecurityProfileName: 'test-security-profile',
        Behaviors: [
          {
            Name: 'CpuUsage',
            Metric: 'cpu-usage',
            Criteria: {
              ComparisonOperator: 'less-than',
              Value: {
                Number: 70
              },
              DurationSeconds: 300
            }
          }
          // Missing connection monitoring behaviors
        ]
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('security profile does not monitor for insecure connections');
  });

  it('should not flag IoT Security Profile that monitors connections', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::SecurityProfile',
      LogicalId: 'TestSecurityProfile',
      Properties: {
        SecurityProfileName: 'test-security-profile',
        Behaviors: [
          {
            Name: 'UnauthorizedConnections',
            Metric: 'destination-ip-addresses',
            Criteria: {
              ComparisonOperator: 'in-cidr-set',
              Value: {
                Cidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
              },
              DurationSeconds: 300
            }
          }
        ]
      }
    };

    const result = IoT005Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});
