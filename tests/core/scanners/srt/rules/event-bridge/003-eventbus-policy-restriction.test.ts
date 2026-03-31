import { describe, it, expect } from 'vitest';
import { Evb003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/event-bridge/003-eventbus-policy-restriction.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Evb003Rule', () => {
  const rule = new Evb003Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::Events::EventBusPolicy resource type', () => {
      expect(rule.appliesTo('AWS::Events::EventBusPolicy')).toBe(true);
    });

    it('should not apply to unsupported resource types', () => {
      expect(rule.appliesTo('AWS::Events::Rule')).toBe(false);
      expect(rule.appliesTo('AWS::Events::EventBus')).toBe(false);
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    it('should return null for unsupported resource types', () => {
      const template: Template = {
        Resources: {
          TestEventRule: {
            Type: 'AWS::Events::Rule',
            Properties: {
              Name: 'test-rule'
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventRule'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null if statement is missing', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default'
              // Statement is missing
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with specific (non-wildcard) principals', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: {
                  AWS: 'arn:aws:iam::123456789012:root'
                },
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with wildcard principal but restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: '*',
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
                Condition: {
                  StringEquals: {
                    'aws:PrincipalAccount': '123456789012'
                  }
                }
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with wildcard principal but aws:PrincipalOrgID condition', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: '*',
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
                Condition: {
                  StringEquals: {
                    'aws:PrincipalOrgID': 'o-1234567890'
                  }
                }
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for policy with wildcard principal but aws:SourceArn condition', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: '*',
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
                Condition: {
                  StringEquals: {
                    'aws:SourceArn': 'arn:aws:lambda:us-east-1:123456789012:function:MyFunction'
                  }
                }
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });

    it('should return null for deny statement with specific principals', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Deny',
                Principal: {
                  AWS: [
                    'arn:aws:iam::111122223333:user/alice',
                    'arn:aws:iam::111122223333:user/bob'
                  ]
                },
                Action: ['events:PutEvents', 'events:PutRule'],
                Resource: 'arn:aws:events:us-east-1:111122223333:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });
    
    it('should handle an array of statements', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: [
                // First statement with specific principal (ok)
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'events:PutEvents',
                  Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
                },
                // Second statement with wildcard but restrictive condition (ok)
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'events:PutEvents',
                  Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default',
                  Condition: {
                    StringEquals: {
                      'aws:PrincipalOrgID': 'o-exampleorgid'
                    }
                  }
                }
              ]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull();
    });
    
    it('should find issue in array of statements when one statement has wildcard without restrictions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: [
                // First statement with specific principal (ok)
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'events:PutEvents',
                  Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
                },
                // Second statement with wildcard and NO restrictive condition (bad)
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'events:PutEvents',
                  Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
                }
              ]
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::EventBusPolicy');
      expect(result?.resourceName).toBe('TestEventBusPolicy');
      expect(result?.issue).toBe('EventBus policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
    });

    it('should return a finding for policy with AWS wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: {
                  AWS: '*'
                },
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::EventBusPolicy');
      expect(result?.resourceName).toBe('TestEventBusPolicy');
      expect(result?.issue).toBe('EventBus policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });

    it('should return a finding for policy with service principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: {
                  Service: 'lambda.amazonaws.com'
                },
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).toBeNull(); // Service principals don't have wildcards, so should pass
    });

    it('should return a finding for policy with direct wildcard principal without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: '*',
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::EventBusPolicy');
      expect(result?.resourceName).toBe('TestEventBusPolicy');
      expect(result?.issue).toBe('EventBus policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });

    it('should return a finding for policy with wildcard in principal array without restrictive conditions', () => {
      const template: Template = {
        Resources: {
          TestEventBusPolicy: {
            Type: 'AWS::Events::EventBusPolicy',
            Properties: {
              EventBusName: 'default',
              Statement: {
                Effect: 'Allow',
                Principal: {
                  AWS: ['arn:aws:iam::123456789012:root', '*']
                },
                Action: 'events:PutEvents',
                Resource: 'arn:aws:events:us-east-1:123456789012:event-bus/default'
              }
            }
          }
        }
      };
        
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestEventBusPolicy'] as Resource);

      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::Events::EventBusPolicy');
      expect(result?.resourceName).toBe('TestEventBusPolicy');
      expect(result?.issue).toBe('EventBus policy allows wildcard principals without restrictive conditions, violating principle of least privilege');
      expect(result?.fix).toBe('Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)');
    });
  });

  describe('evaluate', () => {
    it('should return null for any resource type since it is a stub method', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::Events::EventBusPolicy',
        Properties: {
          Statement: {
            Principal: '*'
          }
        },
        LogicalId: 'TestEventBusPolicy'
      };

      const result = rule.evaluate(resource, stackName);

      expect(result).toBeNull();
    });
  });
});
