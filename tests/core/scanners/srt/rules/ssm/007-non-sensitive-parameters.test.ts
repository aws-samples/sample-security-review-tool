import { describe, it, expect } from 'vitest';
import { SSM003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ssm/007-non-sensitive-parameters.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SSM003Rule', () => {
  const rule = new SSM003Rule();

  it('should pass when parameters are non-sensitive', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({
          parameters: {
            instanceId: {
              type: 'String',
              description: 'EC2 instance identifier'
            },
            region: {
              type: 'String',
              default: 'us-east-1'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when parameter name contains sensitive keywords', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({
          parameters: {
            databasePassword: {
              type: 'String',
              description: 'Database password'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('may contain sensitive data');
  });

  it('should fail when parameter has sensitive default value', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({
          parameters: {
            config: {
              type: 'String',
              default: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('may contain sensitive data');
  });

  it('should fail when parameter description contains sensitive keywords', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({
          parameters: {
            dbConfig: {
              type: 'String',
              description: 'Database secret configuration'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('may contain sensitive data');
  });

  it('should detect various sensitive keywords', () => {
    const sensitiveParams = [
      'apiKey',
      'secretToken',
      'privateKey',
      'credential',
      'certificate',
      'authToken'
    ];

    for (const paramName of sensitiveParams) {
      const resource: CloudFormationResource = {
        Type: 'AWS::SSM::Document',
        LogicalId: 'TestDocument',
        Properties: {
          Content: JSON.stringify({
            parameters: {
              [paramName]: {
                type: 'String'
              }
            }
          })
        }
      };

      const result = rule.evaluate(resource, 'test-stack');
      expect(result).not.toBeNull();
    }
  });

  it('should return null for non-SSM Document resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});