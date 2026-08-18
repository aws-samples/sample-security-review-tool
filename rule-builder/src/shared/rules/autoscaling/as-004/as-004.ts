import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

/**
 * Fixture for AS-004: Auto Scaling Groups attached to a load balancer or
 * target group must use Elastic Load Balancing health checks rather than
 * EC2 instance status checks alone.
 *
 * FINDING: INSTANCE_STATUS_HEALTH_CHECKS_ONLY
 *
 * The AutoScalingGroup below is attached to an ALB target group
 * (populates TargetGroupARNs) but is explicitly configured with
 * HealthCheckType "EC2" (instance status checks only), which triggers
 * the finding because:
 *  - isAttachedToLoadBalancer() -> true (TargetGroupARNs is non-empty)
 *  - usesInstanceStatusHealthChecksOnly() -> true (HealthCheckType === "EC2",
 *    a string that does not name the application/ELB health check type)
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'FixtureVpc', {
      maxAzs: 2,
      natGateways: 0,
    });

    const asg = new autoscaling.AutoScalingGroup(this, 'NonCompliantAsg', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      machineImage: ec2.MachineImage.latestAmazonLinux2023(),
      minCapacity: 1,
      maxCapacity: 1,
      // Non-compliant: relies solely on EC2 instance status checks.
      healthCheck: autoscaling.HealthCheck.ec2(),
    });

    const lb = new elbv2.ApplicationLoadBalancer(this, 'FixtureAlb', {
      vpc,
      internetFacing: false,
    });

    const listener = lb.addListener('FixtureListener', {
      port: 80,
    });

    // Attaching the ASG to a target group populates TargetGroupARNs,
    // making isAttachedToLoadBalancer() return true while the
    // HealthCheckType remains "EC2".
    listener.addTargets('FixtureTargets', {
      port: 80,
      targets: [asg],
    });
  }
}
