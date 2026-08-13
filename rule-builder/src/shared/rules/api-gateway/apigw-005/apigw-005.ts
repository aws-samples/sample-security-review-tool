import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnRestApi } from 'aws-cdk-lib/aws-apigateway';
import { CfnVPCEndpoint } from 'aws-cdk-lib/aws-ec2';

/**
 * Fixture stack for APIGW-005.
 *
 * The control evaluates a single AWS::ApiGateway::RestApi resource at a time and returns on the
 * first matching finding, so each remediation scenario below is expressed on its own RestApi
 * resource, configured so that only the intended scenario's condition is satisfied.
 *
 * A single compliant-looking AWS::EC2::VPCEndpoint resource is declared in the template. Its mere
 * presence satisfies `hasVpcCallers()` for the whole template (used by the PUBLIC_ENDPOINT_TYPE
 * scenario), and it is also referenced directly by the RestApi used for the
 * POLICY_EXCLUDES_PRIVATE_PATH scenario so that it counts as a "compliant" VPC endpoint there.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Supporting resource: an interface VPC endpoint for execute-api that satisfies all of the
    // "compliant VPC endpoint" checks (ServiceName includes execute-api, non-empty SubnetIds and
    // SecurityGroupIds, PrivateDnsEnabled === true). Its logical id is pinned so it can be
    // referenced literally from the RestApi used in the POLICY_EXCLUDES_PRIVATE_PATH scenario and
    // from the access policy's Deny condition below.
    const compliantVpcEndpoint = new CfnVPCEndpoint(this, 'CompliantVpcEndpoint', {
      serviceName: 'com.amazonaws.us-east-1.execute-api',
      vpcId: 'vpc-fake12345',
      vpcEndpointType: 'Interface',
      subnetIds: ['subnet-fake1', 'subnet-fake2'],
      securityGroupIds: ['sg-fake1'],
      privateDnsEnabled: true,
    });
    compliantVpcEndpoint.overrideLogicalId('CompliantVpcEndpoint');

    // Scenario: missing-endpoint-configuration
    // No EndpointConfiguration is declared at all, so the API defaults to a public endpoint.
    new CfnRestApi(this, 'MissingEndpointConfigurationApi', {
      name: 'missing-endpoint-configuration-api',
    });

    // Scenario: public-endpoint-type
    // EndpointConfiguration declares only a public (EDGE) type. hasVpcCallers() is satisfied
    // template-wide by the presence of the AWS::EC2::VPCEndpoint resource declared above.
    new CfnRestApi(this, 'PublicEndpointTypeApi', {
      name: 'public-endpoint-type-api',
      endpointConfiguration: {
        types: ['EDGE'],
      },
    });

    // Scenario: missing-vpc-endpoint
    // The API declares a PRIVATE endpoint type but is not associated with any VPC endpoint.
    new CfnRestApi(this, 'MissingVpcEndpointApi', {
      name: 'missing-vpc-endpoint-api',
      endpointConfiguration: {
        types: ['PRIVATE'],
      },
    });

    // Scenario: policy-excludes-private-path
    // The API is PRIVATE and associated with the compliant VPC endpoint declared above, but its
    // access policy explicitly denies invocations arriving through that VPC endpoint.
    new CfnRestApi(this, 'PolicyExcludesPrivatePathApi', {
      name: 'policy-excludes-private-path-api',
      endpointConfiguration: {
        types: ['PRIVATE'],
        vpcEndpointIds: [compliantVpcEndpoint.ref],
      },
      policy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Deny',
            Principal: '*',
            Action: 'execute-api:Invoke',
            Resource: '*',
            Condition: {
              StringEquals: {
                'aws:sourceVpce': 'CompliantVpcEndpoint',
              },
            },
          },
        ],
      },
    });
  }
}
