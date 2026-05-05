import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

class IoT019Rule extends BaseRule {
  constructor() {
    super(
      'IOT-019',
      'HIGH',
      'IoT resources lack proper monitoring and alerting configuration',
      [
        'AWS::IoT::Thing',
        'AWS::IoT::ThingGroup',
        'AWS::IoTSiteWise::Gateway',
        'AWS::IoTSiteWise::Portal'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) {
      return null;
    }

    if (!allResources) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (cannot verify monitoring configuration)`,
        `Add CloudWatch alarms and notification targets for IoT resource monitoring.`
      );
    }

    const resolver = new CloudFormationResolver(allResources);
    const issues = [];

    // Check for CloudWatch alarms
    if (!this.hasCloudWatchAlarms(resource, resolver)) {
      issues.push('no CloudWatch alarms configured');
    }

    // Check for ownership/notification
    if (!this.hasOwnershipOrNotification(resource, resolver)) {
      issues.push('no owner or notification target assigned');
    }

    if (issues.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (${issues[0]})`,
        `Configure CloudWatch alarms with SNS notifications and assign monitoring ownership.`
      );
    }

    return null;
  }

  private hasCloudWatchAlarms(resource: CloudFormationResource, resolver: CloudFormationResolver): boolean {
    const alarms = resolver.getResourcesByType('AWS::CloudWatch::Alarm');
    return alarms.some(alarm => this.alarmMonitorsResource(alarm, resource));
  }

  private alarmMonitorsResource(alarm: CloudFormationResource, resource: CloudFormationResource): boolean {
    const dimensions = alarm.Properties?.Dimensions || [];
    const alarmName = alarm.Properties?.AlarmName || '';

    return dimensions.some((dim: any) =>
      dim.Value === resource.LogicalId ||
      (typeof dim.Value === 'object' && dim.Value.Ref === resource.LogicalId)
    ) || alarmName.toLowerCase().includes('iot') || alarmName.toLowerCase().includes(resource.LogicalId.toLowerCase());
  }

  private hasOwnershipOrNotification(resource: CloudFormationResource, resolver: CloudFormationResolver): boolean {
    // Check for ownership tags
    const tags = resource.Properties?.Tags || [];
    const hasOwnerTag = tags.some((tag: any) =>
      tag.Key && ['owner', 'team', 'contact', 'responsible'].includes(tag.Key.toLowerCase())
    );

    // Check for SNS topics or notification targets
    const snsTopics = resolver.getResourcesByType('AWS::SNS::Topic');
    const hasNotificationTarget = snsTopics.length > 0;

    return hasOwnerTag || hasNotificationTarget;
  }
}

const iot019RuleInstance = new IoT019Rule();
export { IoT019Rule };
export default iot019RuleInstance;