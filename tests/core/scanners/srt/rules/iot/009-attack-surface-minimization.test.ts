import { describe, it, expect } from 'vitest';
import { IoT009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/009-attack-surface-minimization.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT009Rule', () => {
  const rule = new IoT009Rule();
  const stackName = 'test-stack';

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('IOT-009');
    expect(rule.priority).toBe('HIGH');
  });

  it('should not evaluate non-IoT resources unnecessarily', () => {
    const lambdaFunction = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'test-function',
        Role: { Ref: 'TestRole' }
      },
      LogicalId: 'TestLambda'
    };
    
    const result = rule.evaluate(lambdaFunction, stackName);
    expect(result).toBeNull();
  });

  it('should evaluate IoT Policy resources', () => {
    const iotPolicy = {
      Type: 'AWS::IoT::Policy',
      Properties: {
        PolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Action: '*',
            Resource: '*'
          }]
        }
      },
      LogicalId: 'TestIoTPolicy'
    };
    
    const result = rule.evaluate(iotPolicy, stackName);
    expect(result).not.toBeNull();
  });

  it('should handle object references without crashing', () => {
    const topicRule = {
      Type: 'AWS::IoT::TopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM topic/test',
          Actions: [{
            s3: {
              bucketName: 'test-bucket'
            }
          }]
        }
      },
      LogicalId: 'TestTopicRule'
    };
    
    const result = rule.evaluate(topicRule, stackName, []);
    expect(result).not.toBeNull(); // Should detect SELECT * issue
  });
});