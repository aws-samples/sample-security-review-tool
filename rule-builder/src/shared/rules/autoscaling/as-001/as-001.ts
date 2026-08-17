import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

/**
 * Fixture for AS-001: Auto Scaling Groups must have a nonzero default cooldown period.
 *
 * Triggers all four remediation scenarios by declaring separate Auto Scaling groups,
 * each with a Cooldown property value that maps to a distinct non-compliant CooldownState:
 *   - zero-cooldown:        Cooldown = "0"
 *   - negative-cooldown:    Cooldown = "-1"
 *   - empty-cooldown:       Cooldown = ""
 *   - non-numeric-cooldown: Cooldown = "not-a-number"
 *
 * We use the L1 CfnAutoScalingGroup construct directly because the L2 AutoScalingGroup
 * construct's `cooldown` property is typed as a `Duration`, which cannot represent
 * negative, empty, or non-numeric values -- only the L1 escape hatch lets us set the
 * literal (invalid) string values needed to trigger these scenarios.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'FixtureVpc', {
      maxAzs: 2,
      natGateways: 0,
    });

    const launchTemplate = new ec2.LaunchTemplate(this, 'FixtureLaunchTemplate', {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
    });

    const launchTemplateSpec: autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty = {
      launchTemplateId: launchTemplate.launchTemplateId,
      version: launchTemplate.latestVersionNumber,
    };

    // Scenario: zero-cooldown
    new autoscaling.CfnAutoScalingGroup(this, 'ZeroCooldownAsg', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: vpc.privateSubnets.map((s) => s.subnetId),
      cooldown: '0',
    });

    // Scenario: negative-cooldown
    new autoscaling.CfnAutoScalingGroup(this, 'NegativeCooldownAsg', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: vpc.privateSubnets.map((s) => s.subnetId),
      cooldown: '-1',
    });

    // Scenario: empty-cooldown
    new autoscaling.CfnAutoScalingGroup(this, 'EmptyCooldownAsg', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: vpc.privateSubnets.map((s) => s.subnetId),
      cooldown: '',
    });

    // Scenario: non-numeric-cooldown
    new autoscaling.CfnAutoScalingGroup(this, 'NonNumericCooldownAsg', {
      minSize: '1',
      maxSize: '2',
      launchTemplate: launchTemplateSpec,
      vpcZoneIdentifier: vpc.privateSubnets.map((s) => s.subnetId),
      cooldown: 'not-a-number',
    });
  }
}
