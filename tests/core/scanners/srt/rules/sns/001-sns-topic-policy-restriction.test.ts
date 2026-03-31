import { describe, it, expect } from 'vitest';
import { Sns001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sns/001-sns-topic-policy-restriction.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Sns001Rule', () => {
  const rule = new Sns001Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::SNS::TopicPolicy resource type', () => {
      expect(rule.appliesTo('AWS::SNS::TopicPolicy')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::SNS::Topic')).toBe(false);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for unsupported resource types', () => {
      const template: Template = {
        Resources: {
          TestTopic: {
            Type: 'AWS::SNS::Topic',
            Properties: {
              TopicName: 'test-topic'
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopic'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null if PolicyDocument is missing', () => {
      const template: Template = {
        Resources: {
          TestTopicPolicy: {
            Type: 'AWS::SNS::TopicPolicy',
            Properties: {
              Topics: ['arn:aws:sns:us-east-1:123456789012:mytopic']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopicPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with specific principals', () => {
      const template: Template = {
        Resources: {
          TestTopicPolicy: {
            Type: 'AWS::SNS::TopicPolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'sns:Publish',
                  Resource: 'arn:aws:sns:us-east-1:123456789012:mytopic'
                }
              },
              Topics: ['arn:aws:sns:us-east-1:123456789012:mytopic']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopicPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with wildcard principal but restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestTopicPolicy: {
            Type: 'AWS::SNS::TopicPolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'sns:Publish',
                  Resource: 'arn:aws:sns:us-east-1:123456789012:mytopic',
                  Condition: {
                    StringEquals: {
                      'aws:PrincipalOrgID': 'o-1234567890'
                    }
                  }
                }
              },
              Topics: ['arn:aws:sns:us-east-1:123456789012:mytopic']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopicPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return a finding for policy with wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestTopicPolicy: {
            Type: 'AWS::SNS::TopicPolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'sns:Publish',
                  Resource: 'arn:aws:sns:us-east-1:123456789012:mytopic'
                }
              },
              Topics: ['arn:aws:sns:us-east-1:123456789012:mytopic']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopicPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SNS::TopicPolicy');
      expect(result?.resourceName).toBe('TestTopicPolicy');
      expect(result?.issue).toBe('SNS topic policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });

    it('should return a finding for policy with AWS wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestTopicPolicy: {
            Type: 'AWS::SNS::TopicPolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: {
                    AWS: '*'
                  },
                  Action: 'sns:Subscribe',
                  Resource: 'arn:aws:sns:us-east-1:123456789012:mytopic'
                }
              },
              Topics: ['arn:aws:sns:us-east-1:123456789012:mytopic']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestTopicPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SNS::TopicPolicy');
      expect(result?.resourceName).toBe('TestTopicPolicy');
      expect(result?.issue).toBe('SNS topic policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::SNS::TopicPolicy',
        Properties: {
          PolicyDocument: {
            Statement: {
              Principal: '*'
            }
          }
        },
        LogicalId: 'TestTopicPolicy'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});