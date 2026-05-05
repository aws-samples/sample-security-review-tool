import { describe, it, expect } from 'vitest';
import { SSM001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ssm/005-minimal-input-parameters.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('SSM001Rule', () => {
  const rule = new SSM001Rule();

  it('should pass when document has minimal parameters', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({
          parameters: {
            param1: { type: 'String' },
            param2: { type: 'String' },
            param3: { type: 'String' }
          }
        })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when document has exactly 10 parameters', () => {
    const parameters: any = {};
    for (let i = 1; i <= 10; i++) {
      parameters[`param${i}`] = { type: 'String' };
    }

    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({ parameters })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when document has more than 10 parameters', () => {
    const parameters: any = {};
    for (let i = 1; i <= 15; i++) {
      parameters[`param${i}`] = { type: 'String' };
    }

    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({ parameters })
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('excessive number of input parameters');
    expect(result?.issue).toContain('15 parameters');
  });

  it('should pass when document has no parameters', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::SSM::Document',
      LogicalId: 'TestDocument',
      Properties: {
        Content: JSON.stringify({})
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