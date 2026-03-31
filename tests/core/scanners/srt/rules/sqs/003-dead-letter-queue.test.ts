import { describe, it, expect } from 'vitest';
import { Sqs003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sqs/003-dead-letter-queue.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Sqs003Rule', () => {
  const rule = new Sqs003Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::SQS::Queue resource type', () => {
      expect(rule.appliesTo('AWS::SQS::Queue')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::SQS::QueuePolicy')).toBe(false);
      expect(rule.appliesTo('AWS::SNS::Topic')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for unsupported resource types', () => {
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

    it('should return a finding for queue without RedrivePolicy', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue',
              VisibilityTimeoutSeconds: 300
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::Queue');
      expect(result?.resourceName).toBe('TestQueue');
      expect(result?.issue).toBe('SQS queue does not have a dead-letter queue configured to handle unprocessable messages');
      expect(result?.fix).toBe('Add RedrivePolicy to Properties with deadLetterTargetArn: "arn:aws:sqs:region:account:dlq-name" and maxReceiveCount: 3');
    });

    it('should return a finding for queue with empty properties', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {}
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::Queue');
      expect(result?.resourceName).toBe('TestQueue');
    });

    it('should return null for queue with RedrivePolicy configured', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue',
              RedrivePolicy: {
                deadLetterTargetArn: 'arn:aws:sqs:us-east-1:123456789012:test-dlq',
                maxReceiveCount: 3
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for queue with RedrivePolicy as JSON string', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue',
              RedrivePolicy: '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:test-dlq","maxReceiveCount":5}'
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for queue with RedrivePolicy using CloudFormation references', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue',
              RedrivePolicy: {
                deadLetterTargetArn: {
                  'Fn::GetAtt': ['DeadLetterQueue', 'Arn']
                },
                maxReceiveCount: 10
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).toBeNull();
    });

    it('should return a finding for queue with other properties but no RedrivePolicy', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue',
              VisibilityTimeoutSeconds: 300,
              MessageRetentionPeriod: 1209600
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::Queue');
      expect(result?.resourceName).toBe('TestQueue');
      expect(result?.issue).toBe('SQS queue does not have a dead-letter queue configured to handle unprocessable messages');
      expect(result?.fix).toBe('Add RedrivePolicy to Properties with deadLetterTargetArn: "arn:aws:sqs:region:account:dlq-name" and maxReceiveCount: 3');
    });

    it('should return a finding for FIFO queue without RedrivePolicy', () => {
      const template: Template = {
        Resources: {
          TestQueue: {
            Type: 'AWS::SQS::Queue',
            Properties: {
              QueueName: 'test-queue.fifo',
              FifoQueue: true,
              ContentBasedDeduplication: true
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueue'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::Queue');
      expect(result?.resourceName).toBe('TestQueue');
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::SQS::Queue',
        Properties: {
          QueueName: 'test-queue'
        },
        LogicalId: 'TestQueue'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});