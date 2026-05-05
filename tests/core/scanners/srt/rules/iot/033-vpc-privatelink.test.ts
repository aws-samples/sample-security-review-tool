import { describe, it, expect } from 'vitest';
import IoTSiteWise033Rule from '../../../../../../src/assess/scanning/security-matrix/rules/iot/033-vpc-privatelink.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('IoTSiteWise033Rule', () => {
  it('should return null for non-IoT SiteWise resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      LogicalId: 'TestBucket',
      Properties: {}
    };

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
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
      },
      {
        Type: 'AWS::IoT::RoleAlias',
        LogicalId: 'TestRoleAlias',
        Properties: {
          RoleAlias: 'test-role-alias',
          RoleArn: 'arn:aws:iam::123456789012:role/test-role'
        }
      }
    ];

    // Verify each IoT Core resource is ignored by this SiteWise-specific rule
    for (const resource of resources) {
      const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    }
  });

  it('should flag IoT SiteWise Gateway not deployed in a VPC', () => {
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

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not deployed in a VPC');
  });
  
  it('should detect intrinsic function references in IoT SiteWise Gateway', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'TestGateway',
      Properties: {
        GatewayName: 'test-gateway',
        GatewayPlatform: {
          Greengrass: {
            GroupId: { 'Ref': 'GreengrassGroup' } // Intrinsic function reference
          }
        },
        // Tag that suggests VPC deployment, but we use intrinsic functions
        Tags: [
          {
            Key: 'DeploymentTarget',
            Value: { 'Fn::Sub': '${VPCName}' } // Another intrinsic function
          }
        ]
      }
    };

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('cross-stack references');
  });

  it('should flag IoT SiteWise resource without PrivateLink access', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'test-portal',
        PortalContactEmail: 'test@example.com'
        // Missing VPC configuration
      }
    };

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('not accessible via PrivateLink');
  });
  
  it('should detect intrinsic function references in IoT SiteWise Portal', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: { 'Fn::Join': ['', ['test-portal-', { 'Ref': 'AWS::Region' }]] },
        PortalContactEmail: 'test@example.com',
        PortalVpcConfigurations: [
          {
            VpcId: { 'Ref': 'VPC' }, // Reference to VPC defined in another stack
            SubnetIds: [{ 'Fn::ImportValue': 'ExportedSubnetId' }], // Cross-stack reference
            SecurityGroupIds: [{ 'Ref': 'SecurityGroup' }] // Reference to security group
          }
        ]
      }
    };

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('cross-stack references');
  });

  it('should pass IoT SiteWise Gateway deployed in a VPC', () => {
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

    // Mock allResources with a Greengrass group in a VPC
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::Greengrass::Group',
        LogicalId: 'test-group',
        Properties: {
          Name: 'test-group',
          LatestVersionArn: 'arn:aws:greengrass:us-west-2:123456789012:group/test-group/version/1'
        }
      },
      {
        Type: 'AWS::EC2::Instance',
        LogicalId: 'GreengrassCore',
        Properties: {
          InstanceType: 't3.micro',
          SubnetId: 'subnet-12345',
          UserData: 'IyEvYmluL2Jhc2gKY3VybCAtbyBncmVlbmdyYXNzLXNldHVwLnNoIGh0dHBzOi8vZXhhbXBsZS5jb20vZ3JlZW5ncmFzcy1zZXR1cC5zaAouL2dyZWVuZ3Jhc3Mtc2V0dXAuc2ggLS1ncm91cC1pZCB0ZXN0LWdyb3Vw' // Base64 encoded script that includes 'greengrass'
        }
      },
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'IoTSiteWiseVPCEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-12345']
        }
      }
    ];

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  it('should pass IoT SiteWise Portal with PrivateLink access', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'test-portal',
        PortalContactEmail: 'test@example.com',
        PortalVpcConfigurations: [
          {
            VpcId: 'vpc-12345',
            SubnetIds: ['subnet-12345', 'subnet-67890'],
            SecurityGroupIds: ['sg-12345']
          }
        ]
      }
    };

    // Mock allResources with a VPC endpoint for IoT SiteWise
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'IoTSiteWiseVPCEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-12345']
        }
      }
    ];

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
  
  it('should handle VPC endpoint with intrinsic function in ServiceName', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'TestPortal',
      Properties: {
        PortalName: 'test-portal',
        PortalContactEmail: 'test@example.com',
        PortalVpcConfigurations: [
          {
            VpcId: 'vpc-12345',
            SubnetIds: ['subnet-12345'],
            SecurityGroupIds: ['sg-12345']
          }
        ]
      }
    };

    // Mock allResources with a VPC endpoint using intrinsic function for ServiceName
    const allResources: CloudFormationResource[] = [
      resource,
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'IoTSiteWiseVPCEndpoint',
        Properties: {
          ServiceName: { 'Fn::Sub': 'com.amazonaws.${AWS::Region}.iotsitewise.api' },
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-12345'],
          // Add a tag for additional verification
          Tags: [
            {
              Key: 'Service',
              Value: 'IoTSiteWise'
            }
          ]
        }
      }
    ];

    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });

  it('should return null for non-IoTSiteWise related resources now that direct resource evaluation has been removed', () => {
    const resources: CloudFormationResource[] = [
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'IoTSiteWiseVPCEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcEndpointType: 'Interface',
          SecurityGroupIds: ['sg-12345']
        }
      },
      {
        Type: 'AWS::EC2::SecurityGroup',
        LogicalId: 'IoTSiteWiseSecurityGroup',
        Properties: {
          GroupName: 'IoTSiteWise-SG',
          GroupDescription: 'Security group for IoT SiteWise',
          SecurityGroupEgress: [
            {
              IpProtocol: '-1',
              CidrIp: '0.0.0.0/0'
            }
          ]
        }
      },
      {
        Type: 'AWS::EC2::RouteTable',
        LogicalId: 'IoTSiteWiseRouteTable',
        Properties: {
          VpcId: 'vpc-12345',
          Tags: [
            {
              Key: 'Name',
              Value: 'IoTSiteWise-RT'
            }
          ],
          Routes: [
            {
              DestinationCidrBlock: '0.0.0.0/0',
              GatewayId: 'igw-12345'
            }
          ]
        }
      }
    ];

    // All of these resources should now return null since we've updated the rule
    // to only directly evaluate AWS::IoTSiteWise::* resources
    for (const resource of resources) {
      const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack');
      expect(result).toBeNull();
    }
  });
  
  it('should handle split template scenarios with external VPC resources', () => {
    // This test simulates a split template scenario where VPC resources are in another stack
    // and referenced via cross-stack references or exports/imports
    
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::AssetModel',
      LogicalId: 'TestAssetModel',
      Properties: {
        AssetModelName: 'Test Asset Model',
        // No direct VPC configuration, but has tags indicating external VPC
        Tags: [
          {
            Key: 'VpcId',
            Value: { 'Fn::ImportValue': 'SharedVpcId' }
          }
        ]
      }
    };
    
    // No VPC resources in the current stack
    const allResources: CloudFormationResource[] = [
      resource,
      // Other non-VPC resources
      {
        Type: 'AWS::IoTSiteWise::Asset',
        LogicalId: 'TestAsset',
        Properties: {
          AssetModelId: { 'Ref': 'TestAssetModel' },
          AssetName: 'Test Asset'
        }
      }
    ];
    
    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('cross-stack references');
  });

  /**
   * Test cases that specifically validate the core requirements of IoT033Rule
   * 
   * Core Requirement 1: Deploy IoT SiteWise in VPCs
   * Core Requirement 2: Access via AWS PrivateLink interface endpoints when possible
   * Core Requirement 3: Ensure security groups are properly configured
   */
  
  it('should verify core requirement 1: IoT SiteWise Gateway must be deployed in a VPC', () => {
    // Test case for a gateway with explicit VPC configuration
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Gateway',
      LogicalId: 'GatewayWithVPC',
      Properties: {
        GatewayName: 'vpc-gateway',
        GatewayPlatform: {
          Greengrass: { 
            GroupId: 'greengrass-group-in-vpc' 
          }
        },
        // Explicitly indicate VPC deployment via tags
        Tags: [
          {
            Key: 'Deployment',
            Value: 'VPC'
          }
        ]
      }
    };
    
    // Include VPC resources
    const allResources: CloudFormationResource[] = [
      resource,
      // VPC that contains the gateway
      {
        Type: 'AWS::EC2::VPC',
        LogicalId: 'SiteWiseVPC',
        Properties: {
          CidrBlock: '10.0.0.0/16',
          Tags: [{ Key: 'Name', Value: 'SiteWiseVPC' }]
        }
      },
      // Include VPC endpoint for IoT SiteWise
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'SiteWiseEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcId: { Ref: 'SiteWiseVPC' },
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-private']
        }
      }
    ];
    
    // Should pass because gateway is deployed in a VPC
    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
  
  it('should verify core requirement 2: IoT SiteWise resources must have PrivateLink access', () => {
    // Test case for proper PrivateLink configuration
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Project',
      LogicalId: 'SiteWiseProject',
      Properties: {
        ProjectName: 'vpc-project',
        PortalId: 'portal-with-vpc',
        // Include VPC-related tags
        Tags: [
          {
            Key: 'Network',
            Value: 'Private'
          }
        ]
      }
    };
    
    // Include necessary resources for PrivateLink
    const allResources: CloudFormationResource[] = [
      resource,
      // Portal with VPC configuration
      {
        Type: 'AWS::IoTSiteWise::Portal',
        LogicalId: 'portal-with-vpc',
        Properties: {
          PortalName: 'vpc-portal',
          PortalVpcConfigurations: [
            {
              VpcId: 'vpc-12345',
              SubnetIds: ['subnet-private1', 'subnet-private2'],
              SecurityGroupIds: ['sg-restricted']
            }
          ]
        }
      },
      // VPC endpoint for IoT SiteWise
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'PrivateLinkEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcId: 'vpc-12345',
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-restricted']
        }
      }
    ];
    
    // Should pass because resources have PrivateLink access
    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).toBeNull();
  });
  
  it('should verify core requirement 3: VPC endpoints must not allow unrestricted access', () => {
    // Test case for properly restricted security group
    const resource: CloudFormationResource = {
      Type: 'AWS::IoTSiteWise::Portal',
      LogicalId: 'SecurePortal',
      Properties: {
        PortalName: 'secure-portal',
        PortalContactEmail: 'secure@example.com',
        PortalVpcConfigurations: [
          {
            VpcId: 'vpc-secure',
            SubnetIds: ['subnet-private1'],
            SecurityGroupIds: ['sg-secure']
          }
        ]
      }
    };
    
    // Include VPC endpoint with insecure security group
    const allResources: CloudFormationResource[] = [
      resource,
      // VPC endpoint with overly permissive security group
      {
        Type: 'AWS::EC2::VPCEndpoint',
        LogicalId: 'IoTSiteWiseEndpoint',
        Properties: {
          ServiceName: 'com.amazonaws.us-west-2.iotsitewise.api',
          VpcId: 'vpc-secure',
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-insecure']
        }
      },
      // Security group with unrestricted access
      {
        Type: 'AWS::EC2::SecurityGroup',
        LogicalId: 'sg-insecure',
        Properties: {
          GroupName: 'InsecureGroup',
          GroupDescription: 'Security group with unrestricted access',
          VpcId: 'vpc-secure',
          SecurityGroupIngress: [
            {
              IpProtocol: 'tcp',
              FromPort: 443,
              ToPort: 443,
              CidrIp: '0.0.0.0/0' // Open to the world - insecure!
            }
          ]
        }
      }
    ];
    
    // Should raise an issue due to insecure security group configuration
    const result = IoTSiteWise033Rule.evaluate(resource, 'test-stack', allResources);
    expect(result).not.toBeNull();
    // Note: The actual enforcement of security group restrictions may depend on how 
    // validateVpcEndpointSecurity and sgAllowsUnrestrictedAccess are implemented
  });
});
