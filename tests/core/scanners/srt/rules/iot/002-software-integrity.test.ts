import { describe, it, expect } from 'vitest';
import IoT002Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/002-software-integrity.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoT002Rule', () => {
  // Helper function to create a basic IoT Thing resource
  const createIoTThing = (overrides = {}): CloudFormationResource => {
    return {
      Type: 'AWS::IoT::Thing',
      LogicalId: 'TestThing',
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {}
        }
      },
      ...overrides
    };
  };

  // Helper function to create a Signer Signing Profile
  const createSigningProfile = (overrides = {}): CloudFormationResource => {
    return {
      Type: 'AWS::Signer::SigningProfile',
      LogicalId: 'TestSigningProfile',
      Properties: {
        PlatformId: 'AmazonFreeRTOS-Default',
        SignatureValidityPeriod: {
          Type: 'DAYS',
          Value: 90
        }
      },
      ...overrides
    };
  };

  // Helper function to create an IAM Role
  const createIAMRole = (overrides = {}): CloudFormationResource => {
    return {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestIoTRole',
      Properties: {
        RoleName: 'IoTDeviceCodeAccess',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iot.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        Policies: [
          {
            PolicyName: 'IoTDeviceCodeAccess',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: [
                    'codecommit:GitPull',
                    'codecommit:GitPush'
                  ],
                  Resource: 'arn:aws:codecommit:*:*:test-iot-repo',
                  Condition: {
                    StringEquals: {
                      'aws:PrincipalTag/Role': 'IoTDeveloper'
                    }
                  }
                },
                {
                  Effect: 'Deny',
                  Action: [
                    'codecommit:DeleteRepository',
                    'codecommit:DeleteBranch'
                  ],
                  Resource: '*'
                }
              ]
            }
          }
        ]
      },
      ...overrides
    };
  };

  // Helper function to create an IoT Job
  const createIoTJob = (overrides = {}): CloudFormationResource => {
    return {
      Type: 'AWS::IoT::Job',
      LogicalId: 'TestIoTJob',
      Properties: {
        Targets: ['test-thing'],
        Document: {
          CodeSigning: {
            StartSigningJobParameter: {
              Destination: {
                S3Destination: {
                  Bucket: 'iot-firmware-bucket',
                  Key: 'signed-firmware.bin'
                }
              },
              SigningProfileName: 'TestSigningProfile'
            }
          },
          Operation: 'Firmware_Update'
        }
      },
      ...overrides
    };
  };

  it('should return null for non-IoT resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Thing with no software integrity attributes', () => {
    // Create a thing with no integrity attributes
    const resource = createIoTThing();

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing software integrity tracking');
  });

  it('should pass IoT Thing with software integrity attributes', () => {
    // Create a thing with software integrity attributes
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            softwareVersion: '1.0.0',
            firmwareVersion: '2.1.5',
            signatureVerification: 'true'
          }
        }
      }
    });

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass IoT Thing with firmware version attribute', () => {
    // Create a thing with firmware version attribute
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            firmwareVersion: '2.1.5'
          }
        }
      }
    });

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass IoT Thing with integrity check attribute', () => {
    // Create a thing with integrity check attribute
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            integrityCheck: 'enabled'
          }
        }
      }
    });

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag IoT Thing with missing software integrity attributes', () => {
    // Create a thing without software integrity attributes
    const resource = createIoTThing();

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing software integrity tracking');
  });

  it('should flag IoT Thing Group without software integrity policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::ThingGroup',
      LogicalId: 'TestThingGroup',
      Properties: {
        ThingGroupName: 'test-thing-group'
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('missing software integrity policy');
  });

  it('should pass IoT Thing Group with software integrity policy in attributes', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::ThingGroup',
      LogicalId: 'TestThingGroup',
      Properties: {
        ThingGroupName: 'test-thing-group',
        ThingGroupProperties: {
          AttributePayload: {
            Attributes: {
              softwareIntegrityPolicy: 'enabled',
              verificationFrequency: 'daily'
            }
          }
        }
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass IoT Thing Group with software integrity policy in tags', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::ThingGroup',
      LogicalId: 'TestThingGroup',
      Properties: {
        ThingGroupName: 'test-thing-group',
        Tags: [
          {
            Key: 'software-integrity',
            Value: 'true'
          }
        ]
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate AWS Signer Signing Profile (non-IoT resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Signer::SigningProfile',
      LogicalId: 'TestSigningProfile',
      Properties: {
        PlatformId: 'Generic-Platform',
        SignatureValidityPeriod: {
          Type: 'DAYS',
          Value: 10
        }
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate AWS Signer Signing Profile (non-IoT resource)', () => {
    const resource = createSigningProfile();

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should check IoT Jobs for code signing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoT::Job',
      LogicalId: 'TestIoTJob',
      Properties: {
        Targets: ['test-thing'],
        Document: {
          // Missing code signing configuration
          Operation: 'Firmware_Update'
        }
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('job lacks code signing');
  });

  it('should pass IoT Job with code signing', () => {
    const resource = createIoTJob();

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate IAM Role (non-IoT resource)', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestIoTRole',
      Properties: {
        RoleName: 'IoTDeviceCodeAccess',
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Service: 'iot.amazonaws.com'
              },
              Action: 'sts:AssumeRole'
            }
          ]
        },
        Policies: [
          {
            PolicyName: 'IoTDeviceCodeAccess',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*'
                }
              ]
            }
          }
        ]
      }
    };

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not evaluate IAM Role (non-IoT resource)', () => {
    const resource = createIAMRole();

    const result = IoT002Rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when both required integrity methods are implemented', () => {
    // Create a thing with software integrity attributes
    const resource = createIoTThing({
      Properties: {
        ThingName: 'test-thing',
        AttributePayload: {
          Attributes: {
            softwareVersion: '1.0.0',
            firmwareVersion: '2.1.5',
            signatureVerification: 'true'
          }
        }
      }
    });

    // Create mock resources with both required integrity methods
    const allResources: CloudFormationResource[] = [
      resource,
      // Code signing
      createIoTJob(),
      createSigningProfile(),
      // Secure access
      createIAMRole()
    ];

    const result = IoT002Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
});
