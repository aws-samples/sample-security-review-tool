import { describe, it, expect } from 'vitest';
import IoT018Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/018-logging-strategy.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT018Rule', () => {
  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Logging Options without log level', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::LoggingOptions',
      LogicalId: 'TestLoggingOptions',
      Properties: {
        RoleArn: 'arn:aws:iam::123456789012:role/IoTLoggingRole'
        // Missing LogLevel
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('logging options not properly configured');
  });

  it('should flag IoT Logging Options with disabled log level', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::LoggingOptions',
      LogicalId: 'TestLoggingOptions',
      Properties: {
        LogLevel: 'DISABLED',
        RoleArn: 'arn:aws:iam::123456789012:role/IoTLoggingRole'
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('logging options not properly configured');
  });

  it('should flag IoT Logging Options without role ARN', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::LoggingOptions',
      LogicalId: 'TestLoggingOptions',
      Properties: {
        LogLevel: 'INFO'
        // Missing RoleArn
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('logging options not properly configured');
  });

  it('should not flag properly configured IoT Logging Options', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::LoggingOptions',
      LogicalId: 'TestLoggingOptions',
      Properties: {
        LogLevel: 'INFO',
        RoleArn: 'arn:aws:iam::123456789012:role/IoTLoggingRole'
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate AWS::Logs::LogGroup (non-IoT resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Logs::LogGroup',
      LogicalId: 'TestLogGroup',
      Properties: {
        LogGroupName: '/aws/iot/test-log-group'
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate AWS::Logs::LogGroup (non-IoT resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Logs::LogGroup',
      LogicalId: 'TestLogGroup',
      Properties: {
        LogGroupName: '/aws/iot/test-log-group',
        RetentionInDays: 3
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag properly configured IoT Log Group', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Logs::LogGroup',
      LogicalId: 'TestLogGroup',
      Properties: {
        LogGroupName: '/aws/iot/test-log-group',
        RetentionInDays: 30
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag non-IoT Log Group', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Logs::LogGroup',
      LogicalId: 'TestLogGroup',
      Properties: {
        LogGroupName: '/aws/lambda/test-function',
        // Missing RetentionInDays, but this is not an IoT log group
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Topic Rule without logging actions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              DynamoDB: {
                TableName: 'test-table',
                HashKeyField: 'id',
                HashKeyValue: '${topic()}'
              }
            }
          ]
          // Missing logging actions and error action
        }
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('topic rule lacks logging configuration');
  });

  it('should not flag IoT Topic Rule with CloudWatch Logs action', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              CloudwatchLogs: {
                LogGroupName: '/aws/iot/test-log-group',
                RoleArn: 'arn:aws:iam::123456789012:role/IoTLoggingRole'
              }
            }
          ]
        }
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag IoT Topic Rule with Firehose action', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              Firehose: {
                DeliveryStreamName: 'test-delivery-stream',
                RoleArn: 'arn:aws:iam::123456789012:role/IoTFirehoseRole'
              }
            }
          ]
        }
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag IoT Topic Rule with error action', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              DynamoDB: {
                TableName: 'test-table',
                HashKeyField: 'id',
                HashKeyValue: '${topic()}'
              }
            }
          ],
          ErrorAction: {
            CloudwatchLogs: {
              LogGroupName: '/aws/iot/errors',
              RoleArn: 'arn:aws:iam::123456789012:role/IoTLoggingRole'
            }
          }
        }
      }
    };

    const result = IoT018Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag IoT Topic Rule with Lambda action that has logging', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::TopicRule',
      LogicalId: 'TestTopicRule',
      Properties: {
        TopicRulePayload: {
          Sql: 'SELECT * FROM "iot/test"',
          Actions: [
            {
              Lambda: {
                FunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
              }
            }
          ]
        }
      }
    };

    // Mock Lambda function with tracing enabled
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'TestFunction',
        Properties: {
          FunctionName: 'test-function',
          TracingConfig: {
            Mode: 'Active'
          }
        }
      }
    ];

    const result = IoT018Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
});
