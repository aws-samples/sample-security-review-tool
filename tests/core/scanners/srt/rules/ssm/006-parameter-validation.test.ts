import { describe, it, expect } from 'vitest';
import { SSM002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ssm/006-parameter-validation.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SSM002Rule', () => {
  const rule = new SSM002Rule();

  it('should pass when parameter has allowedPattern', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Automation',
        Content: JSON.stringify({
          parameters: {
            instanceId: {
              type: 'String',
              allowedPattern: '^i-[0-9a-f]{8,17}$'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when parameter has allowedValues', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Automation',
        Content: JSON.stringify({
          parameters: {
            environment: {
              type: 'String',
              allowedValues: ['dev', 'staging', 'prod']
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when parameter is Boolean type', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Automation',
        Content: JSON.stringify({
          parameters: {
            enableFeature: {
              type: 'Boolean'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when parameter has default value', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Automation',
        Content: JSON.stringify({
          parameters: {
            timeout: {
              type: 'String',
              default: '300'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when parameter lacks validation constraints', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Automation',
        Content: JSON.stringify({
          parameters: {
            userInput: {
              type: 'String'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('parameter lacks validation constraints');
  });

  it('should return null for non-Automation documents', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        DocumentType: 'Command',
        Content: JSON.stringify({
          parameters: {
            userInput: {
              type: 'String'
            }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
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