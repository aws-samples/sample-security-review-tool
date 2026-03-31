import { describe, it, expect } from 'vitest';
import { Sqs008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/sqs/008-sqs-vpc-endpoint-enforcement.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Sqs008Rule', () => {
  const rule = new Sqs008Rule();
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
    it('should return null for policy with VPC endpoint enforcement using aws:SourceVpce', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: [
                  {
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:user/worker' },
                    Action: 'sqs:SendMessage',
                    Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue'
                  },
                  {
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 'sqs:*',
                    Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue',
                    Condition: {
                      StringNotEquals: {
                        'aws:SourceVpce': 'vpce-12345678'
                      }
                    }
                  }
                ]
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with VPC endpoint enforcement using aws:SourceVpc', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: [
                  {
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:user/worker' },
                    Action: 'sqs:ReceiveMessage',
                    Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue'
                  },
                  {
                    Effect: 'Deny',
                    Principal: '*',
                    Action: 'sqs:*',
                    Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue',
                    Condition: {
                      StringNotEquals: {
                        'aws:SourceVpc': 'vpc-12345678'
                      }
                    }
                  }
                ]
              },
              Queues: ['https://sqs.us-east-1.amazonaws.com/123456789012/myqueue']
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestQueuePolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy without VPC conditions (no private connectivity intent)', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/worker' },
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

    it('should return a finding for policy with VPC conditions but only Allow statements', () => {
      const template: Template = {
        Resources: {
          TestQueuePolicy: {
            Type: 'AWS::SQS::QueuePolicy',
            Properties: {
              PolicyDocument: {
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::123456789012:user/worker' },
                  Action: 'sqs:SendMessage',
                  Resource: 'arn:aws:sqs:us-east-1:123456789012:myqueue',
                  Condition: {
                    StringEquals: {
                      'aws:sourceVpce': 'vpce-12345678'
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

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::SQS::QueuePolicy');
      expect(result?.resourceName).toBe('TestQueuePolicy');
      expect(result?.issue).toBe('Consider adding VPC endpoint enforcement if this workload requires private network connectivity to SQS');
      expect(result?.fix).toBe('Add Deny statement with Condition: { "StringNotEquals": { "aws:sourceVpce": "vpce-ENDPOINT_ID" } } to enforce VPC endpoint usage');
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