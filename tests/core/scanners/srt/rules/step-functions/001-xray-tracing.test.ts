import { describe, it, expect } from 'vitest';
import { StepFunctions001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/step-functions/001-xray-tracing.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('StepFunctions001Rule - Step Functions X-Ray Tracing Tests', () => {
  const rule = new StepFunctions001Rule();
  const stackName = 'test-stack';

  // Helper function to create Step Functions state machine test resources
  function createStateMachineResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::StepFunctions::StateMachine',
      Properties: {
        StateMachineType: 'STANDARD',
        Definition: {
          StartAt: 'FirstState',
          States: {
            FirstState: {
              Type: 'Pass',
              End: true
            }
          }
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestStateMachine'
    };
  }

  describe('X-Ray Supported Services Detection Tests', () => {
    it('should detect Lambda integrations', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              Parameters: {
                FunctionName: 'MyFunction',
                Payload: {}
              },
              End: true
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('lacks X-Ray tracing');
    });

    it('should detect API Gateway integrations', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'CallAPI',
          States: {
            CallAPI: {
              Type: 'Task',
              Resource: 'arn:aws:states:::apigateway:invoke',
              Parameters: {
                ApiEndpoint: 'example.com',
                Method: 'GET'
              },
              End: true
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('lacks X-Ray tracing');
    });

    it('should detect SQS integrations', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'SendMessage',
          States: {
            SendMessage: {
              Type: 'Task',
              Resource: 'arn:aws:states:::sqs:sendMessage',
              Parameters: {
                QueueUrl: 'https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue',
                MessageBody: {}
              },
              End: true
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('lacks X-Ray tracing');
    });

    it('should detect multiple supported services', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              Next: 'SendMessage'
            },
            SendMessage: {
              Type: 'Task',
              Resource: 'arn:aws:states:::sqs:sendMessage',
              End: true
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('lacks X-Ray tracing');
    });

    it('should not apply to state machines without supported service integrations', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'Wait',
          States: {
            Wait: {
              Type: 'Wait',
              Seconds: 10,
              Next: 'Pass'
            },
            Pass: {
              Type: 'Pass',
              End: true
            }
          }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Tracing Configuration Tests', () => {
    it('should detect missing TracingConfiguration', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        }
        // No TracingConfiguration
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Add TracingConfiguration property');
    });

    it('should detect disabled tracing', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        },
        TracingConfiguration: {
          Enabled: false
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Set TracingConfiguration.Enabled to true');
    });

    it('should accept enabled tracing', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        },
        TracingConfiguration: {
          Enabled: true
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Intrinsic Function Tests', () => {
    it('should handle intrinsic functions in Definition', () => {
      const resource = createStateMachineResource({
        Definition: { 'Ref': 'StateMachineDefinition' },
        TracingConfiguration: {
          Enabled: true
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't determine if there are supported services
    });

    it('should handle intrinsic functions in TracingConfiguration', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        },
        TracingConfiguration: { 'Ref': 'TracingConfig' }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull(); // Can't determine if tracing is enabled
      expect(result?.fix).toContain('Add TracingConfiguration property');
    });

    it('should handle intrinsic functions in Enabled property', () => {
      const resource = createStateMachineResource({
        Definition: {
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        },
        TracingConfiguration: {
          Enabled: { 'Ref': 'TracingEnabled' }
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).not.toBeNull(); // Can't determine if tracing is enabled
      expect(result?.fix).toContain('Set TracingConfiguration.Enabled to true');
    });

    it('should detect supported services in string definition', () => {
      const resource = createStateMachineResource({
        Definition: JSON.stringify({
          StartAt: 'InvokeLambda',
          States: {
            InvokeLambda: {
              Type: 'Task',
              Resource: 'arn:aws:states:::lambda:invoke',
              End: true
            }
          }
        }),
        TracingConfiguration: {
          Enabled: true
        }
      });

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Tracing is enabled
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::StepFunctions::StateMachine',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't determine if there are supported services
    });

    it('should handle missing Definition', () => {
      const resource = createStateMachineResource({
        // No Definition
        TracingConfiguration: {
          Enabled: true
        }
      });
      
      delete resource.Properties.Definition;
      
      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Can't determine if there are supported services
    });

    it('should ignore non-Step Functions resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });
  });
});
