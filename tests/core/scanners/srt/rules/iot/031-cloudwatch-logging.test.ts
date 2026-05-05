import { describe, it, expect } from 'vitest';
import IoTSiteWise031Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/031-cloudwatch-logging.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoTSiteWise031Rule', () => {
  it('should return null for non-IoT SiteWise resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
  
  it('should return null for general IoT Core resources (not SiteWise)', () => {
    const resources: CloudFormationResource[] = [
      {
        Type: 'AWS::IoT::Thing',
        LogicalId: 'TestThing',
        Properties: {
          ThingName: 'test-thing'
        }
      },
      {
        Type: 'AWS::IoT::Policy',
        LogicalId: 'TestPolicy',
        Properties: {
          PolicyName: 'test-policy',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: ['iot:Connect'],
                Resource: '*'
              }
            ]
          }
        }
      },
      {
        Type: 'AWS::IoT::TopicRule',
        LogicalId: 'TestTopicRule',
        Properties: {
          RuleName: 'test-rule',
          TopicRulePayload: {
            Actions: [
              {
                S3: {
                  BucketName: 'test-bucket',
                  Key: 'test-key'
                }
              }
            ],
            Sql: "SELECT * FROM 'test/topic'"
          }
        }
      }
    ];

    // Verify each IoT Core resource is ignored by this SiteWise-specific rule
    for (const resource of resources) {
      const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    }
  });

  it('should flag IoT SiteWise Gateway without logging enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: 'test-group'
          }
        }
      }
    };

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('logging not enabled');
  });

  it('should flag IoT SiteWise Gateway with logging but no alerts', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: 'test-group'
          }
        },
        LoggingOptions: {
          Level: 'INFO'
        }
      }
    };

    // Mock allResources with a Log Group but no alerts
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::Logs::LogGroup',
        LogicalId: 'IoTSiteWiseLogGroup',
        Properties: {
          LogGroupName: '/aws/iotsitewise/gateway/test-gateway'
        }
      }
    ];

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('no alerts configured');
  });

  it('should flag IoT SiteWise Gateway with logging and alerts but no owner', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: 'test-group'
          }
        },
        LoggingOptions: {
          Level: 'INFO'
        }
      }
    };

    // Mock allResources with a Log Group and alerts but no owner
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::Logs::LogGroup',
        LogicalId: 'IoTSiteWiseLogGroup',
        Properties: {
          LogGroupName: '/aws/iotsitewise/gateway/test-gateway'
        }
      },
      {
        Type: 'AWS::CloudWatch::Alarm',
        LogicalId: 'IoTSiteWiseErrorAlarm',
        Properties: {
          AlarmName: 'IoTSiteWise-Error-Alarm',
          Namespace: 'AWS/IoTSiteWise',
          MetricName: 'ErrorCount',
          Dimensions: [
            {
              Name: 'GatewayId',
              Value: 'test-gateway'
            }
          ],
          Threshold: 1,
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          Period: 300,
          Statistic: 'Sum',
          AlarmActions: []
        }
      }
    ];

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('no owner assigned');
  });

  it('should pass IoT SiteWise Gateway with logging, alerts, and owner', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: 'test-group'
          }
        },
        LoggingOptions: {
          Level: 'INFO'
        }
      }
    };

    // Mock allResources with a Log Group, alerts, and owner
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::Logs::LogGroup',
        LogicalId: 'IoTSiteWiseLogGroup',
        Properties: {
          LogGroupName: '/aws/iotsitewise/gateway/test-gateway'
        }
      },
      {
        Type: 'AWS::CloudWatch::Alarm',
        LogicalId: 'IoTSiteWiseErrorAlarm',
        Properties: {
          AlarmName: 'IoTSiteWise-Error-Alarm',
          Namespace: 'AWS/IoTSiteWise',
          MetricName: 'ErrorCount',
          Dimensions: [
            {
              Name: 'GatewayId',
              Value: 'test-gateway'
            }
          ],
          Threshold: 1,
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          Period: 300,
          Statistic: 'Sum',
          AlarmActions: ['arn:aws:sns:us-west-2:123456789012:IoTSiteWiseAlerts']
        }
      },
      {
        Type: 'AWS::SNS::Topic',
        LogicalId: 'IoTSiteWiseAlertsTopic',
        Properties: {
          TopicName: 'IoTSiteWiseAlerts'
        }
      },
      {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'IoTSiteWiseLogProcessor',
        Properties: {
          FunctionName: 'IoTSiteWiseLogProcessor',
          Handler: 'index.handler',
          Role: 'arn:aws:iam::123456789012:role/IoTSiteWiseLogProcessorRole',
          Code: {
            ZipFile: 'exports.handler = async (event) => { console.log("Processing IoT SiteWise logs"); };'
          }
        }
      }
    ];

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  it('should return null for non-IoTSiteWise related resources now that direct resource evaluation has been removed', () => {
    const resources: CloudFormationResource[] = [
      // Log Group that previously would be flagged
      {
        Type: 'AWS::Logs::LogGroup',
        LogicalId: 'IoTSiteWiseLogGroup',
        Properties: {
          LogGroupName: '/aws/iotsitewise/gateway/test-gateway'
        }
      },
      // IAM Role that previously would be flagged
      {
        Type: 'AWS::IAM::Role',
        LogicalId: 'IoTSiteWiseRole',
        Properties: {
          RoleName: 'IoTSiteWiseRole',
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: {
                  Service: 'iotsitewise.amazonaws.com'
                },
                Action: 'sts:AssumeRole'
              }
            ]
          },
          Policies: [
            {
              PolicyName: 'IoTSiteWisePolicy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: [
                      'iotsitewise:*'
                    ],
                    Resource: '*'
                  }
                  // Missing CloudWatch Logs permissions
                ]
              }
            }
          ]
        }
      },
      // CloudWatch Alarm that previously would be flagged
      {
        Type: 'AWS::CloudWatch::Alarm',
        LogicalId: 'IoTSiteWiseErrorAlarm',
        Properties: {
          AlarmName: 'IoTSiteWise-Error-Alarm',
          Namespace: 'AWS/IoTSiteWise',
          MetricName: 'ErrorCount',
          Dimensions: [
            {
              Name: 'GatewayId',
              Value: 'test-gateway'
            }
          ],
          Threshold: 1,
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          Period: 300,
          Statistic: 'Sum'
          // Missing AlarmActions
        }
      },
      // EventBridge Rule that previously would be flagged
      {
        Type: 'AWS::Events::Rule',
        LogicalId: 'IoTSiteWiseLogRule',
        Properties: {
          Name: 'IoTSiteWiseLogRule',
          EventPattern: {
            source: ['aws.iotsitewise'],
            'detail-type': ['IoT SiteWise Gateway Metric']
          }
          // Missing Targets
        }
      }
    ];

    // All of these resources should now return null since we've updated the rule
    // to only directly evaluate AWS::IoTSiteWise::* resources
    for (const resource of resources) {
      const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    }
  });

  it('should still evaluate IoTSiteWise resources with related supporting resources in allResources', () => {
    // IoT SiteWise Gateway that should pass with proper supporting resources
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: 'test-group'
          }
        }
      }
    };

    // Mock allResources with everything needed for proper logging
    const allResources: CloudFormationResource[] = [
      resource,
      // Log Group
      {
        Type: 'AWS::Logs::LogGroup',
        LogicalId: 'IoTSiteWiseLogGroup',
        Properties: {
          LogGroupName: '/aws/iotsitewise/gateway/test-gateway'
        }
      },
      // IAM Role with CloudWatch Logs permissions
      {
        Type: 'AWS::IAM::Role',
        LogicalId: 'IoTSiteWiseRole',
        Properties: {
          RoleName: 'IoTSiteWiseRole',
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: {
                  Service: 'iotsitewise.amazonaws.com'
                },
                Action: 'sts:AssumeRole'
              }
            ]
          },
          Policies: [
            {
              PolicyName: 'IoTSiteWisePolicy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: [
                      'iotsitewise:*',
                      'logs:CreateLogGroup',
                      'logs:CreateLogStream',
                      'logs:PutLogEvents'
                    ],
                    Resource: '*'
                  }
                ]
              }
            }
          ]
        }
      },
      // CloudWatch Alarm with notification actions
      {
        Type: 'AWS::CloudWatch::Alarm',
        LogicalId: 'IoTSiteWiseErrorAlarm',
        Properties: {
          AlarmName: 'IoTSiteWise-Error-Alarm',
          Namespace: 'AWS/IoTSiteWise',
          MetricName: 'ErrorCount',
          Dimensions: [
            {
              Name: 'GatewayId',
              Value: 'test-gateway'
            }
          ],
          Threshold: 1,
          ComparisonOperator: 'GreaterThanThreshold',
          EvaluationPeriods: 1,
          Period: 300,
          Statistic: 'Sum',
          AlarmActions: ['arn:aws:sns:us-west-2:123456789012:IoTSiteWiseAlerts']
        }
      },
      // Lambda for log processing (owner)
      {
        Type: 'AWS::Lambda::Function',
        LogicalId: 'IoTSiteWiseLogProcessor',
        Properties: {
          FunctionName: 'IoTSiteWiseLogProcessor',
          Handler: 'index.handler',
          Role: 'arn:aws:iam::123456789012:role/IoTSiteWiseLogProcessorRole',
          Code: {
            ZipFile: 'exports.handler = async (event) => { console.log("Processing IoT SiteWise logs"); };'
          }
        }
      }
    ];

    const result = IoTSiteWise031Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
});
