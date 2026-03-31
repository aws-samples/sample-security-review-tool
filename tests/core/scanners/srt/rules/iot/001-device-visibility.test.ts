import { describe, it, expect } from 'vitest';
import IoT001Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/001-device-visibility.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

// Helper function to create a basic IoT Thing resource
const createIoTThing = (overrides = {}): CloudFormationResource => {
  return {
    Type: 'AWS::IoT::Thing',
    LogicalId: 'TestThing',
    Properties: {
      ThingName: 'test-thing',
      AttributePayload: {
        Attributes: {
          location: 'warehouse'
        }
      },
      Tags: [
        {
          Key: 'Environment',
          Value: 'Production'
        }
      ]
    },
    ...overrides
  };
};

// Helper function to create a CloudWatch alarm for a thing
const createCloudWatchAlarm = (thingName: string): CloudFormationResource => {
  return {
    Type: 'AWS::CloudWatch::Alarm',
    LogicalId: `${thingName}Alarm`,
    Properties: {
      AlarmName: `${thingName}Alarm`,
      AlarmDescription: `Alarm for ${thingName}`,
      MetricName: 'ConnectionCount',
      Namespace: 'AWS/IoT',
      Dimensions: [
        {
          Name: 'ThingName',
          Value: thingName
        }
      ],
      Threshold: 0,
      ComparisonOperator: 'LessThanThreshold',
      EvaluationPeriods: 1,
      Period: 300,
      Statistic: 'Sum'
    }
  };
};

describe('IoT001Rule', () => {
  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT001Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Thing without proper device registry attributes', () => {
    // Create a thing with missing essential attributes
    const resource = createIoTThing();

    // Create mock resources with no alerting
    const allResources: CloudFormationResource[] = [resource];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not properly registered in AWS IoT device registry');
  });

  it('should flag IoT Thing without Fleet Hub integration', () => {
    // Create a thing with device registry attributes but no Fleet Hub integration
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            manufacturer: 'TestManufacturer',
            model: 'TestModel',
            serialNumber: '12345',
            deviceType: 'sensor'
          }
        },
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    });

    // Create mock resources with no alerting
    const allResources: CloudFormationResource[] = [resource];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not integrated with AWS IoT Device Management Fleet Hub');
  });

  it('should flag IoT Thing with only device registry but no other requirements', () => {
    // Create a thing with device registry attributes but no Fleet Hub, alerting, or ownership
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            manufacturer: 'TestManufacturer',
            model: 'TestModel',
            serialNumber: '12345',
            deviceType: 'sensor'
            // No fleetId or other Fleet Hub integration
          }
        },
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
          // No ownership tags
        ]
      }
    });

    // Create mock resources with no alerting
    const allResources: CloudFormationResource[] = [resource];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not integrated with AWS IoT Device Management Fleet Hub');
    expect(result?.issue).toContain('missing alerting mechanisms');
    expect(result?.issue).toContain('no owner assigned');
  });
  
  it('should pass IoT Thing with device registry and Fleet Hub integration', () => {
    // Create a thing with device registry attributes and Fleet Hub integration
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            manufacturer: 'TestManufacturer',
            model: 'TestModel',
            serialNumber: '12345',
            deviceType: 'sensor',
            fleetId: 'fleet-123' // Has Fleet Hub integration
          }
        },
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
          // No ownership tags
        ]
      }
    });

    // Create mock resources with no alerting
    const allResources: CloudFormationResource[] = [resource];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull(); // Should pass with device registry and Fleet Hub
  });

  it('should not flag properly configured IoT Thing', () => {
    // Create a fully compliant thing
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            manufacturer: 'TestManufacturer',
            model: 'TestModel',
            serialNumber: '12345',
            deviceType: 'sensor',
            fleetId: 'fleet-123' // Has Fleet Hub integration
          }
        },
        Tags: [
          {
            Key: 'Owner',
            Value: 'IoT-Team'
          },
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    });

    // Mock allResources with a CloudWatch alarm for this thing
    const allResources: CloudFormationResource[] = [
      resource,
      createCloudWatchAlarm('test-thing')
    ];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
  
  it('should pass IoT Thing with alternative ownership indicators', () => {
    // Create a thing with device registry attributes, Fleet Hub integration, and alerting
    // but ownership indicated by name rather than tags or attributes
    const resource = createIoTThing({
      Properties: {
        ThingName: 'team-sensors-device1', // Name indicates ownership
        AttributePayload: {
          Attributes: {
            manufacturer: 'TestManufacturer',
            model: 'TestModel',
            serialNumber: '12345',
            deviceType: 'sensor',
            fleetId: 'fleet-123' // Has Fleet Hub integration
          }
        },
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    });

    // Mock allResources with a CloudWatch alarm for this thing
    const allResources: CloudFormationResource[] = [
      resource,
      createCloudWatchAlarm('team-sensors-device1')
    ];

    const result = IoT001Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  it('should flag IoT ThingGroup without Fleet Hub integration and ownership', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::ThingGroup',
      LogicalId: 'TestThingGroup',
      Properties: {
        ThingGroupName: 'test-thing-group',
        // Missing ownership tags and Fleet Hub integration
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    };

    const result = IoT001Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not integrated with AWS IoT Device Management Fleet Hub');
    expect(result?.issue).toContain('no owner assigned');
  });
  
  it('should pass IoT ThingGroup with Fleet Hub integration via name', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::ThingGroup',
      LogicalId: 'TestThingGroup',
      Properties: {
        ThingGroupName: 'fleet-managed-sensors', // Name indicates Fleet Hub integration
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    };

    const result = IoT001Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull(); // Should pass with 1 out of 2 checks (Fleet Hub integration)
  });

  it('should pass IoT Policy even without ownership assignment due to threshold', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Policy',
      LogicalId: 'TestPolicy',
      Properties: {
        PolicyName: 'test-policy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'iot:Connect',
              Resource: '*'
            }
          ]
        },
        // Missing ownership tags
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    };

    const result = IoT001Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull(); // Should pass due to threshold of 0 for policies
  });
  
  it('should pass IoT Policy with Fleet Hub references in policy document', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Policy',
      LogicalId: 'TestPolicy',
      Properties: {
        PolicyName: 'test-policy',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: 'iot:Connect',
              Resource: '*',
              Condition: {
                StringEquals: {
                  'iot:ClientId': ['fleet-device-*']
                }
              }
            }
          ]
        },
        Tags: [
          {
            Key: 'Environment',
            Value: 'Production'
          }
        ]
      }
    };

    const result = IoT001Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull(); // Should pass due to Fleet Hub reference in policy
  });
});
