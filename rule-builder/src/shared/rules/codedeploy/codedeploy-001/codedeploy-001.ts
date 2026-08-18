import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as codedeploy from 'aws-cdk-lib/aws-codedeploy';

export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const application = new codedeploy.ServerApplication(this, 'ServerApplication');

    // FINDING: NO_ALARM_MONITORING
    // No CloudWatch alarms are associated with this deployment group (the `alarms`
    // prop is omitted), so CDK does not emit an AlarmConfiguration property at all.
    // The adapter treats an absent AlarmConfiguration as "no alarms configured",
    // triggering the NO_ALARM_MONITORING finding.
    new codedeploy.ServerDeploymentGroup(this, 'DeploymentGroupNoAlarms', {
      application,
      deploymentGroupName: 'no-alarm-monitoring-dg',
    });
  }
}
