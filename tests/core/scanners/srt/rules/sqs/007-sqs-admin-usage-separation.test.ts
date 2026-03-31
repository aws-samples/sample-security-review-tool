import { describe, it, expect } from 'vitest';
import { Sqs007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sqs/007-sqs-admin-usage-separation.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Sqs007Rule', () => {
  const rule = new Sqs007Rule();
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
    it('should return null for policy with only admin actions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/admin' },
                  Action: ['sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:SetQueueAttributes'],
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

    it('should return null for policy with only usage actions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/worker' },
                  Action: ['sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage'],
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

    it('should return a finding for Allow policy with both admin and usage actions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/poweruser' },
                  Action: ['sqs:CreateQueue', 'sqs:SendMessage', 'sqs:ReceiveMessage'],
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
      expect(result?.issue).toBe('SQS policy grants both administrative and usage permissions to the same principal, violating principle of least privilege');
      expect(result?.fix).toBe('Separate admin actions [sqs:CreateQueue] from usage actions [sqs:SendMessage, sqs:ReceiveMessage] into different statements');
    });

    it('should return a finding for Deny policy with both admin and usage actions', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Deny',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/restricted' },
                  Action: ['sqs:DeleteQueue', 'sqs:SendMessage'],
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
      expect(result?.issue).toBe('SQS policy grants both administrative and usage permissions to the same principal, violating principle of least privilege');
      expect(result?.fix).toBe('Separate admin actions [sqs:DeleteQueue] from usage actions [sqs:SendMessage] into different statements');
    });

    it('should return a finding for policy with sqs:* action', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/superuser' },
                  Action: 'sqs:*',
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
      expect(result?.issue).toBe('SQS policy grants both administrative and usage permissions to the same principal, violating principle of least privilege');
      expect(result?.fix).toBe('Separate admin actions [sqs:*] from usage actions [sqs:*] into different statements');
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::SQS::QueuePolicy',
        Properties: {},
        LogicalId: 'TestQueuePolicy'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});