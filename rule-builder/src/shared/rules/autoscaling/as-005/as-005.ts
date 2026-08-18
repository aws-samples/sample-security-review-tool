import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnAutoScalingGroup, CfnLaunchConfiguration } from 'aws-cdk-lib/aws-autoscaling';

export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Supporting launch configuration for the LAUNCH_CONFIGURATION_ONLY finding.
    const launchConfiguration = new CfnLaunchConfiguration(this, 'LegacyLaunchConfiguration', {
      imageId: 'ami-0123456789abcdef0',
      instanceType: 't3.micro',
    });

    // Finding: LAUNCH_CONFIGURATION_ONLY
    // The group is wired to a launch configuration only -- no launch template, no mixed
    // instances policy.
    new CfnAutoScalingGroup(this, 'LaunchConfigurationOnlyAsg', {
      minSize: '1',
      maxSize: '2',
      availabilityZones: ['us-east-1a'],
      launchConfigurationName: launchConfiguration.ref,
    });

    // Finding: EXISTING_INSTANCE_SOURCE
    // The group takes its instance configuration from an existing EC2 instance id, with no
    // launch configuration, launch template, or mixed instances policy declared.
    new CfnAutoScalingGroup(this, 'ExistingInstanceSourceAsg', {
      minSize: '1',
      maxSize: '2',
      availabilityZones: ['us-east-1a'],
      instanceId: 'i-0123456789abcdef0',
    });

    // Finding: MIXED_INSTANCES_POLICY_WITHOUT_LAUNCH_TEMPLATE
    // A mixed instances policy is declared, but its launch template specification names
    // neither a launch template id nor a launch template name, so no launch template is
    // actually in effect.
    new CfnAutoScalingGroup(this, 'MixedInstancesPolicyWithoutLaunchTemplateAsg', {
      minSize: '1',
      maxSize: '2',
      availabilityZones: ['us-east-1a'],
      mixedInstancesPolicy: {
        launchTemplate: {
          launchTemplateSpecification: {
            version: '1',
          },
        },
      },
    });

    // Finding: UNUSABLE_LAUNCH_TEMPLATE_REFERENCE
    // A direct launch template reference is declared, but it supplies neither a launch
    // template id nor a launch template name, so it identifies no launch template.
    new CfnAutoScalingGroup(this, 'UnusableLaunchTemplateReferenceAsg', {
      minSize: '1',
      maxSize: '2',
      availabilityZones: ['us-east-1a'],
      launchTemplate: {
        version: '1',
      },
    });

    // Finding: NO_LAUNCH_SOURCE
    // No launch configuration, launch template, mixed instances policy, or existing
    // instance id is declared at all.
    new CfnAutoScalingGroup(this, 'NoLaunchSourceAsg', {
      minSize: '1',
      maxSize: '2',
      availabilityZones: ['us-east-1a'],
    });
  }
}
