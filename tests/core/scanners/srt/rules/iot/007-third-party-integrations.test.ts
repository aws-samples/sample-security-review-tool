import { describe, it, expect } from 'vitest';
import { IoT007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/iot/007-third-party-integrations.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT007Rule', () => {
  const rule = new IoT007Rule();
  const stackName = 'test-stack';

  it('should have correct rule properties', () => {
    expect(rule.id).toBe('IOT-007');
    expect(rule.priority).toBe('HIGH');
  });

  it('should not evaluate non-IoT resources', () => {
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

  it('should evaluate IoT TopicRule resources', () => {
    const topicRule = {
      Type: 'AWS::IoT::TopicRule',
      Properties: {
        TopicRulePayload: {
          Actions: [{
            http: {
              url: 'https://api.example.com'
            }
          }]
        }
      },
      LogicalId: 'TestTopicRule'
    };
    
    const result = rule.evaluate(topicRule, stackName);
    expect(result).not.toBeNull();
  });

  it('should handle object references without crashing', () => {
    const topicRule = {
      Type: 'AWS::IoT::TopicRule',
      Properties: {
        TopicRulePayload: {
          Actions: [{
            lambda: {
              functionArn: { Ref: 'TestLambda' }
            }
          }]
        }
      },
      LogicalId: 'TestTopicRule'
    };
    
    const result = rule.evaluate(topicRule, stackName, []);
    expect(result).toBeNull(); // Should not crash with object reference
  });
});