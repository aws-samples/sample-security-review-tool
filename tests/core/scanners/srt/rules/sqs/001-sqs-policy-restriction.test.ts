import { describe, it, expect } from 'vitest';
import { Sqs001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sqs/001-sqs-policy-restriction.cf.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Sqs001Rule', () => {
  const rule = new Sqs001Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::SQS::QueuePolicy resource type', () => {
      expect(rule.appliesTo('AWS::SQS::QueuePolicy')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::SQS::Queue')).toBe(false);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for unsupported resource types', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue'
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null if PolicyDocument is missing', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with specific principals', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'sqs:SendMessage',
                  Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue'
                }
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with wildcard principal but restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'sqs:SendMessage',
                  Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue',
                  Condition: {
                    StringEquals: {
                      'aws:PrincipalAccount': '123456789012'
                    }
                  }
                }
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return a finding for policy with wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'sqs:SendMessage',
                  Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue'
                }
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::QueuePolicy');
      expect(result?.resourceName).toBe('TestQueuePolicy');
      expect(result?.issue).toBe('SQS policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });

    it('should return a finding for policy with AWS wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: {
                    AWS: '*'
                  },
                  Action: 'sqs:ReceiveMessage',
                  Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue'
                }
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::QueuePolicy');
      expect(result?.resourceName).toBe('TestQueuePolicy');
      expect(result?.issue).toBe('SQS policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::SQS::QueuePolicy',
        Properties: {
          PolicyDocument: {
            Statement: {
              Principal: '*'
            }
          }
        },
        LogicalId: 'TestQueuePolicy'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});