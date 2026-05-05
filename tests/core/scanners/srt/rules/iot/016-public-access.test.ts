import { describe, it, expect } from 'vitest';
import IoT016Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/016-public-access.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT016Rule', () => {
  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Policy that allows public access', () => {
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
          ]
        }
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('policy allows public access');
  });

  it('should not flag IoT Policy that requires authentication', () => {
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
              Resource: 'arn:aws:iot:us-east-1:123456789012:client/${iot:Certificate.ID}'
            }
          ]
        }
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Topic Rule without authentication', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              Lambda: {
                FunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
              }
            }
          ]
        }
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('topic rule lacks proper authentication');
  });

  it('should not flag IoT Topic Rule with authentication check', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test" WHERE clientid() = "device-001"',
          Actions: [
            {
              Lambda: {
                FunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
              }
            }
          ]
        }
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag IoT Topic Rule with authorizer', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          AuthorizerName: 'test-authorizer',
          Actions: [
            {
              Lambda: {
                FunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
              }
            }
          ]
        }
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Authorizer that is not active', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Authorizer',
      LogicalId: 'TestAuthorizer',
      Properties: {
        AuthorizerName: 'test-authorizer',
        Status: 'INACTIVE',
        AuthorizerFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-authorizer'
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('authorizer not properly configured');
  });

  it('should flag IoT Authorizer with signing disabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Authorizer',
      LogicalId: 'TestAuthorizer',
      Properties: {
        AuthorizerName: 'test-authorizer',
        Status: 'ACTIVE',
        SigningDisabled: true,
        AuthorizerFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-authorizer'
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('authorizer not properly configured');
  });

  it('should not flag properly configured IoT Authorizer', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Authorizer',
      LogicalId: 'TestAuthorizer',
      Properties: {
        AuthorizerName: 'test-authorizer',
        Status: 'ACTIVE',
        SigningDisabled: false,
        AuthorizerFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-authorizer'
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Domain Configuration without authentication', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::DomainConfiguration',
      LogicalId: 'TestDomainConfiguration',
      Properties: {
        DomainConfigurationName: 'test-domain',
        AuthenticationType: 'NONE'
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('domain configuration lacks authentication');
  });

  it('should flag IoT Domain Configuration with custom auth but missing certificates', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::DomainConfiguration',
      LogicalId: 'TestDomainConfiguration',
      Properties: {
        DomainConfigurationName: 'test-domain',
        AuthenticationType: 'CUSTOM_AUTH'
        // Missing ServerCertificateArn and ValidationCertificateArn
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('domain configuration lacks authentication');
  });

  it('should not flag properly configured IoT Domain Configuration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::DomainConfiguration',
      LogicalId: 'TestDomainConfiguration',
      Properties: {
        DomainConfigurationName: 'test-domain',
        AuthenticationType: 'CUSTOM_AUTH',
        ServerCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abcdef12-3456-7890-abcd-ef1234567890',
        ValidationCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/fedcba98-7654-3210-fedc-ba9876543210'
      }
    };

    const result = IoT016Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});
