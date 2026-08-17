import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

/**
 * Fixture stack for AS-006: Auto Scaling groups must span at least two Availability Zones,
 * either via a list of Availability Zones or via subnets (VPCZoneIdentifier) that reside in
 * different Availability Zones.
 *
 * Each scenario is triggered by a dedicated AWS::AutoScaling::AutoScalingGroup resource,
 * using AWS::EC2::Subnet resources with literal AvailabilityZone values so that the rule's
 * static template analysis can resolve the placement.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 1,
      natGateways: 0,
    });

    const launchTemplate = new ec2.CfnLaunchTemplate(this, 'LaunchTemplate', {
      launchTemplateData: {
        imageId: 'ami-0123456789abcdef0',
        instanceType: 't3.micro',
      },
    });

    const launchTemplateSpec: autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty = {
      launchTemplateId: launchTemplate.ref,
      version: launchTemplate.attrLatestVersionNumber,
    };

    // --- Scenario: no-placement-specified ---
    // No AvailabilityZones and no VPCZoneIdentifier declared at all.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgNoPlacement', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
    });

    // --- Scenario: single-availability-zone ---
    // A single Availability Zone declared, no subnets.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgSingleZone', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      availabilityZones: ['us-east-1a'],
    });

    // --- Scenario: single-subnet ---
    // No AvailabilityZones declared, exactly one subnet referenced.
    const subnetSingle = new ec2.CfnSubnet(this, 'SubnetSingle', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.100.0/24',
      availabilityZone: 'us-east-1a',
    });
    new autoscaling.CfnAutoScalingGroup(this, 'AsgSingleSubnet', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: [subnetSingle.ref],
    });

    // --- Scenario: subnets-in-single-availability-zone ---
    // No AvailabilityZones declared, two-or-more subnets, all in the same AZ.
    const subnetSharedA = new ec2.CfnSubnet(this, 'SubnetSharedA', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.101.0/24',
      availabilityZone: 'us-east-1a',
    });
    const subnetSharedB = new ec2.CfnSubnet(this, 'SubnetSharedB', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.102.0/24',
      availabilityZone: 'us-east-1a',
    });
    new autoscaling.CfnAutoScalingGroup(this, 'AsgSharedSubnetZone', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: [subnetSharedA.ref, subnetSharedB.ref],
    });

    // --- Scenario: placement-in-single-availability-zone ---
    // A single declared Availability Zone plus subnets that reside in that same zone,
    // so the declared zones and subnet zones combined still cover only one zone.
    const subnetCombinedA = new ec2.CfnSubnet(this, 'SubnetCombinedA', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.103.0/24',
      availabilityZone: 'us-east-1a',
    });
    const subnetCombinedB = new ec2.CfnSubnet(this, 'SubnetCombinedB', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.104.0/24',
      availabilityZone: 'us-east-1a',
    });
    new autoscaling.CfnAutoScalingGroup(this, 'AsgSharedCombinedZone', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      availabilityZones: ['us-east-1a'],
      vpcZoneIdentifier: [subnetCombinedA.ref, subnetCombinedB.ref],
    });

    // --- Scenario: subnet-outside-declared-availability-zones ---
    // A single declared Availability Zone, and subnets that all reside in a different,
    // single Availability Zone than the one declared.
    const subnetMismatchA = new ec2.CfnSubnet(this, 'SubnetMismatchA', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.105.0/24',
      availabilityZone: 'us-east-1b',
    });
    const subnetMismatchB = new ec2.CfnSubnet(this, 'SubnetMismatchB', {
      vpcId: vpc.vpcId,
      cidrBlock: '10.0.106.0/24',
      availabilityZone: 'us-east-1b',
    });
    new autoscaling.CfnAutoScalingGroup(this, 'AsgMismatchedZone', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      availabilityZones: ['us-east-1a'],
      vpcZoneIdentifier: [subnetMismatchA.ref, subnetMismatchB.ref],
    });
  }
}
