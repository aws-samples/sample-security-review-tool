import { describe, it, expect } from 'vitest';
import { ApiGw005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/api-gateway/005-vpc-privatelink.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ApiGw005Rule', () => {
  const rule = new ApiGw005Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::ApiGateway::RestApi', () => {
      it('should return a finding if a public API is used with VPC-connected resources', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

        const ec2Instance: CloudFormationResource = {
          Type: 'AWS::EC2::Instance',
          Properties: {
            InstanceType: 't3.micro',
            ImageId: 'ami-12345678'
          },
          LogicalId: 'TestInstance'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, ec2Instance]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
        expect(result?.resourceName).toBe('TestApi');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('public API with VPC-connected resources');
      });

      it('should return a finding if a private API has no VPC endpoints', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'private-api',
            EndpointConfiguration: {
              Types: ['PRIVATE']
            }
          },
          LogicalId: 'TestApi'
        };

        const lambdaFunction: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Handler: 'index.handler',
            Runtime: 'nodejs14.x',
            Code: {
              ZipFile: 'exports.handler = async (event) => { return { statusCode: 200, body: JSON.stringify("Hello") }; };'
            },
            VpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              SecurityGroupIds: ['sg-12345678']
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, lambdaFunction]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
        expect(result?.resourceName).toBe('TestApi');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('no API Gateway VPC endpoints found');
      });

      it('should return a finding if a private API has improperly configured VPC endpoints', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'private-api',
            EndpointConfiguration: {
              Types: ['PRIVATE']
            }
          },
          LogicalId: 'TestApi'
        };

        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            // Missing SubnetIds, SecurityGroupIds, and PrivateDnsEnabled
          },
          LogicalId: 'TestVpcEndpoint'
        };

        const lambdaFunction: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Handler: 'index.handler',
            Runtime: 'nodejs14.x',
            Code: {
              ZipFile: 'exports.handler = async (event) => { return { statusCode: 200, body: JSON.stringify("Hello") }; };'
            },
            VpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              SecurityGroupIds: ['sg-12345678']
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, vpcEndpoint, lambdaFunction]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::ApiGateway::RestApi');
        expect(result?.resourceName).toBe('TestApi');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('VPC endpoints found but not properly configured');
      });

      it('should not return a finding if a private API has properly configured VPC endpoints', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'private-api',
            EndpointConfiguration: {
              Types: ['PRIVATE']
            }
          },
          LogicalId: 'TestApi'
        };

        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            SecurityGroupIds: ['sg-12345678'],
            PrivateDnsEnabled: true
          },
          LogicalId: 'TestVpcEndpoint'
        };

        const lambdaFunction: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Handler: 'index.handler',
            Runtime: 'nodejs14.x',
            Code: {
              ZipFile: 'exports.handler = async (event) => { return { statusCode: 200, body: JSON.stringify("Hello") }; };'
            },
            VpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              SecurityGroupIds: ['sg-12345678']
            }
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, vpcEndpoint, lambdaFunction]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if there are no VPC-connected resources', () => {
        // Arrange
        const api: CloudFormationResource = {
          Type: 'AWS::ApiGateway::RestApi',
          Properties: {
            Name: 'public-api',
            EndpointConfiguration: {
              Types: ['REGIONAL']
            }
          },
          LogicalId: 'TestApi'
        };

        const lambdaFunction: CloudFormationResource = {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Handler: 'index.handler',
            Runtime: 'nodejs14.x',
            Code: {
              ZipFile: 'exports.handler = async (event) => { return { statusCode: 200, body: JSON.stringify("Hello") }; };'
            }
            // No VpcConfig
          },
          LogicalId: 'TestFunction'
        };

        // Act
        const result = rule.evaluate(api, stackName, [api, lambdaFunction]);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('AWS::EC2::VPCEndpoint', () => {
      it('should return a finding if an API Gateway VPC endpoint is missing VpcId', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            // Missing VpcId
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            SecurityGroupIds: ['sg-12345678'],
            PrivateDnsEnabled: true
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EC2::VPCEndpoint');
        expect(result?.resourceName).toBe('TestVpcEndpoint');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('missing VPC ID');
      });

      it('should return a finding if an API Gateway VPC endpoint is missing SubnetIds', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            // Missing SubnetIds
            SecurityGroupIds: ['sg-12345678'],
            PrivateDnsEnabled: true
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EC2::VPCEndpoint');
        expect(result?.resourceName).toBe('TestVpcEndpoint');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('missing subnet IDs');
      });

      it('should return a finding if an API Gateway VPC endpoint is missing SecurityGroupIds', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            // Missing SecurityGroupIds
            PrivateDnsEnabled: true
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EC2::VPCEndpoint');
        expect(result?.resourceName).toBe('TestVpcEndpoint');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('missing security group IDs');
      });

      it('should return a finding if an API Gateway VPC endpoint has PrivateDnsEnabled set to false', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            SecurityGroupIds: ['sg-12345678'],
            PrivateDnsEnabled: false
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EC2::VPCEndpoint');
        expect(result?.resourceName).toBe('TestVpcEndpoint');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('private DNS not enabled');
      });

      it('should return a finding if an API Gateway VPC endpoint has VpcEndpointType set to Gateway', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            VpcEndpointType: 'Gateway'
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EC2::VPCEndpoint');
        expect(result?.resourceName).toBe('TestVpcEndpoint');
        expect(result?.issue).toContain('API Gateway does not use VPC PrivateLink for VPC-connected entities');
        expect(result?.issue).toContain('API Gateway requires Interface VPC endpoints, not Gateway');
      });

      it('should not return a finding if an API Gateway VPC endpoint is properly configured', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.execute-api',
            VpcId: 'vpc-12345678',
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            SecurityGroupIds: ['sg-12345678'],
            PrivateDnsEnabled: true,
            VpcEndpointType: 'Interface'
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for non-API Gateway VPC endpoints', () => {
        // Arrange
        const vpcEndpoint: CloudFormationResource = {
          Type: 'AWS::EC2::VPCEndpoint',
          Properties: {
            ServiceName: 'com.amazonaws.us-east-1.s3',
            VpcId: 'vpc-12345678',
            RouteTableIds: ['rtb-12345678']
          },
          LogicalId: 'TestVpcEndpoint'
        };

        // Act
        const result = rule.evaluate(vpcEndpoint, stackName, [vpcEndpoint]);

        // Assert
        expect(result).toBeNull();
      });
    });

    it('should return null for non-applicable resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if allResources is not provided', () => {
      // Arrange
      const api: CloudFormationResource = {
        Type: 'AWS::ApiGateway::RestApi',
        Properties: {
          Name: 'public-api',
          EndpointConfiguration: {
            Types: ['REGIONAL']
          }
        },
        LogicalId: 'TestApi'
      };

      // Act
      const result = rule.evaluate(api, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
