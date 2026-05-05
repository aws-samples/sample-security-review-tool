import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoTSiteWise-031 Rule: Enable IoT SiteWise logging to AWS CloudWatch.
 * 
 * Documentation: "AWS IoT SiteWise IoTSiteWise-031: Enable IoT SiteWise logging to AWS CloudWatch. IoT SiteWise logging is disabled by default. 
 * Assign an owner to monitor SiteWise logs and set alerts on exceptional resource usage.
 * See https://docs.aws.amazon.com/iot-sitewise/latest/userguide/monitor-cloudwatch-logs.html"
 * 
 * IMPORTANT: This rule is specifically targeted at IoT SiteWise resources only, not general IoT Core resources.
 * It evaluates only AWS::IoTSiteWise:: resources and related CloudWatch resources that monitor SiteWise components.
 */
export class IoT031Rule extends BaseRule {
  constructor() {
    super(
      'IOTSITEWISE-031',
      'HIGH',
      'IoT SiteWise logging to CloudWatch not properly configured',
      [
        'AWS::IoTSiteWise::Gateway',
        'AWS::IoTSiteWise::AssetModel',
        'AWS::IoTSiteWise::Asset',
        'AWS::IoTSiteWise::Portal',
        'AWS::IoTSiteWise::AccessPolicy',
        'AWS::IoTSiteWise::Dashboard',
        'AWS::IoTSiteWise::Project'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (missing Properties)`,
        `Configure CloudWatch logging for IoT SiteWise resources.`
      );
    }

    // All resources that pass the appliesTo check are IoT SiteWise resources
    return this.evaluateIoTSiteWiseResource(resource, stackName, allResources);
  }

  /**
   * Evaluate IoT SiteWise resources for CloudWatch logging configuration
   */
  private evaluateIoTSiteWiseResource(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const issues = [];

    // Check if logging is enabled for this resource
    if (!this.hasLoggingEnabled(resource, allResources)) {
      issues.push('logging not enabled for IoT SiteWise resource');
    }

    // Check if there are alerts configured for this resource
    if (!this.hasAlertsConfigured(resource, allResources)) {
      issues.push('no alerts configured for IoT SiteWise resource');
    }

    // Check if there's an owner assigned to monitor logs
    if (!this.hasOwnerAssigned(resource, allResources)) {
      issues.push('no owner assigned to monitor logs');
    }

    // If any issues were found, create a scan result with all issues
    if (issues.length > 0) {
      const issueMessage = `${this.description} (${issues[0]})`;
      const fix = this.getActionForIssue(issues[0]);
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    return null;
  }

  /**
   * Get the appropriate action message for an issue
   */
  private getActionForIssue(issue: string): string {
    if (issue.includes('logging not enabled')) {
      return 'Enable CloudWatch logging for IoT SiteWise resources.';
    } else if (issue.includes('no alerts configured')) {
      return 'Configure CloudWatch alarms for exceptional resource usage.';
    } else if (issue.includes('no owner assigned')) {
      return 'Assign an owner to monitor SiteWise logs.';
    } else {
      return 'Configure proper CloudWatch logging for IoT SiteWise resources.';
    }
  }


  /**
   * Check if logging is enabled for an IoT SiteWise resource
   */
  private hasLoggingEnabled(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    // For IoT SiteWise Gateway, check if logging is explicitly enabled
    if (resource.Type === 'AWS::IoTSiteWise::Gateway') {
      const gatewayJson = JSON.stringify(resource.Properties || {});
      if (gatewayJson.includes('LoggingOptions') || gatewayJson.includes('LogLevel')) {
        return true;
      }
    }

    // Check if there's a Log Group for IoT SiteWise
    const hasIoTSiteWiseLogGroup = allResources.some(res =>
      res.Type === 'AWS::Logs::LogGroup' && this.isIoTSiteWiseLogGroup(res)
    );

    // Check if there's an IAM Role with permissions to write to CloudWatch Logs
    const hasIoTSiteWiseRoleWithLogsPermissions = allResources.some(res =>
      res.Type === 'AWS::IAM::Role' &&
      this.isIoTSiteWiseRole(res) &&
      this.hasCloudWatchLogsPermissions(res)
    );

    return hasIoTSiteWiseLogGroup || hasIoTSiteWiseRoleWithLogsPermissions;
  }


  /**
   * Check if an owner is assigned to monitor logs for an IoT SiteWise resource
   * This checks for explicit ownership indicators and cross-template references
   */
  private hasOwnerAssigned(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    // Direct ownership indicators
    const hasDirectOwnership = this.hasDirectOwnershipIndicators(resource, allResources);

    // Check ownership tags on the resource itself
    const hasOwnershipTag = this.hasOwnershipTags(resource);

    // Check if alarms have notification actions (indicating monitoring)
    const hasAlarmsWithNotifications = allResources.some(res =>
      res.Type === 'AWS::CloudWatch::Alarm' &&
      this.isIoTSiteWiseAlarm(res) &&
      this.hasNotificationActions(res)
    );

    return hasDirectOwnership || hasOwnershipTag || hasAlarmsWithNotifications;
  }

  /**
   * Check for direct ownership indicators (Lambda functions, SNS topics, Dashboards)
   */
  private hasDirectOwnershipIndicators(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check for Lambda functions that process IoT SiteWise logs
    const hasLogProcessingLambda = allResources.some(res =>
      res.Type === 'AWS::Lambda::Function' &&
      this.isLogProcessingFunction(res)
    );

    // Check for SNS topics that receive IoT SiteWise log notifications
    const hasNotificationTopic = allResources.some(res =>
      res.Type === 'AWS::SNS::Topic' &&
      this.isNotificationTopic(res)
    );

    // Check for CloudWatch Dashboards for IoT SiteWise monitoring
    const hasCloudWatchDashboard = allResources.some(res =>
      res.Type === 'AWS::CloudWatch::Dashboard' &&
      this.isDashboardForIoTSiteWise(res)
    );

    return hasLogProcessingLambda || hasNotificationTopic || hasCloudWatchDashboard;
  }

  /**
   * Check if a Log Group is for IoT SiteWise
   */
  private isIoTSiteWiseLogGroup(resource: CloudFormationResource): boolean {
    const logGroupName = resource.Properties?.LogGroupName || '';

    return typeof logGroupName === 'string' && (
      logGroupName.includes('IoTSiteWise') ||
      logGroupName.includes('iot-sitewise') ||
      logGroupName.includes('/aws/iotsitewise/') ||
      logGroupName.includes('SiteWise')
    );
  }

  /**
   * Check if an IAM Role is for IoT SiteWise
   */
  private isIoTSiteWiseRole(resource: CloudFormationResource): boolean {
    const roleName = resource.Properties?.RoleName || '';
    const roleJson = JSON.stringify(resource);

    return roleJson.includes('iotsitewise') ||
      roleJson.includes('IoTSiteWise') ||
      roleJson.includes('SiteWise') ||
      (typeof roleName === 'string' && (
        roleName.includes('IoTSiteWise') ||
        roleName.includes('iot-sitewise') ||
        roleName.includes('SiteWise')
      ));
  }

  /**
   * Check if an IAM Role has permissions to write to CloudWatch Logs
   */
  private hasCloudWatchLogsPermissions(resource: CloudFormationResource): boolean {
    // Check AssumeRolePolicyDocument
    const assumeRolePolicyDocument = resource.Properties?.AssumeRolePolicyDocument;
    if (assumeRolePolicyDocument) {
      const policyJson = JSON.stringify(assumeRolePolicyDocument);
      if (policyJson.includes('logs:') &&
        (policyJson.includes('logs:PutLogEvents') ||
          policyJson.includes('logs:CreateLogStream') ||
          policyJson.includes('logs:CreateLogGroup'))) {
        return true;
      }
    }

    // Check inline policies
    const policies = resource.Properties?.Policies;
    if (policies && Array.isArray(policies)) {
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;
        if (policyDocument) {
          const policyJson = JSON.stringify(policyDocument);
          if (policyJson.includes('logs:') &&
            (policyJson.includes('logs:PutLogEvents') ||
              policyJson.includes('logs:CreateLogStream') ||
              policyJson.includes('logs:CreateLogGroup'))) {
            return true;
          }
        }
      }
    }

    // Check managed policy ARNs
    const managedPolicyArns = resource.Properties?.ManagedPolicyArns;
    if (managedPolicyArns && Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (typeof arn === 'string' &&
          (arn.includes('CloudWatchLogsFullAccess') ||
            arn.includes('CloudWatchAgentServerPolicy'))) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if a CloudWatch Alarm is for IoT SiteWise
   */
  private isIoTSiteWiseAlarm(resource: CloudFormationResource): boolean {
    const alarmName = resource.Properties?.AlarmName || '';
    const namespace = resource.Properties?.Namespace || '';
    const dimensions = resource.Properties?.Dimensions || [];
    const alarmJson = JSON.stringify(resource);

    // Check if the alarm is explicitly for IoT SiteWise
    if (typeof alarmName === 'string' && (
      alarmName.includes('IoTSiteWise') ||
      alarmName.includes('iot-sitewise') ||
      alarmName.includes('SiteWise')
    )) {
      return true;
    }

    // Check if the alarm uses IoT SiteWise namespace
    if (namespace === 'AWS/IoTSiteWise') {
      return true;
    }

    // Check if the alarm has dimensions related to IoT SiteWise
    if (Array.isArray(dimensions)) {
      for (const dimension of dimensions) {
        if (dimension.Name && (
          dimension.Name === 'GatewayId' ||
          dimension.Name === 'AssetId' ||
          dimension.Name === 'PropertyId'
        )) {
          return true;
        }
      }
    }

    // Check if the alarm references IoT SiteWise in its configuration
    return alarmJson.includes('iotsitewise') ||
      alarmJson.includes('IoTSiteWise') ||
      alarmJson.includes('SiteWise');
  }

  /**
   * Check if a CloudWatch Alarm has notification actions
   */
  private hasNotificationActions(resource: CloudFormationResource): boolean {
    const alarmActions = resource.Properties?.AlarmActions;
    const insufficientDataActions = resource.Properties?.InsufficientDataActions;
    const okActions = resource.Properties?.OKActions;

    return (Array.isArray(alarmActions) && alarmActions.length > 0) ||
      (Array.isArray(insufficientDataActions) && insufficientDataActions.length > 0) ||
      (Array.isArray(okActions) && okActions.length > 0);
  }

  /**
   * Check if alerts are configured for an IoT SiteWise resource
   */
  private hasAlertsConfigured(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }


    // Check for CloudWatch Alarms monitoring IoT SiteWise metrics
    const hasCloudWatchAlarms = allResources.some(res =>
      res.Type === 'AWS::CloudWatch::Alarm' &&
      this.isIoTSiteWiseAlarm(res)
    );

    // Check for EventBridge Rules triggered by IoT SiteWise log events
    const hasEventRules = allResources.some(res =>
      res.Type === 'AWS::Events::Rule' &&
      this.isIoTSiteWiseEventRule(res)
    );

    // Check for Metric Filters for IoT SiteWise logs
    const hasMetricFilters = allResources.some(res =>
      res.Type === 'AWS::Logs::MetricFilter' &&
      JSON.stringify(res.Properties || {}).includes('IoTSiteWise')
    );

    return hasCloudWatchAlarms || hasEventRules || hasMetricFilters;
  }

  /**
   * Check if an EventBridge Rule is for IoT SiteWise logs
   */
  private isIoTSiteWiseEventRule(resource: CloudFormationResource): boolean {
    const ruleName = resource.Properties?.Name || '';
    const eventPattern = resource.Properties?.EventPattern;
    const ruleJson = JSON.stringify(resource);

    // Check if the rule name indicates it's for IoT SiteWise
    if (typeof ruleName === 'string' && (
      ruleName.includes('IoTSiteWise') ||
      ruleName.includes('iot-sitewise') ||
      ruleName.includes('SiteWise')
    )) {
      return true;
    }

    // Check if the event pattern includes IoT SiteWise events
    if (eventPattern) {
      const eventPatternJson = JSON.stringify(eventPattern);
      if (eventPatternJson.includes('iotsitewise') ||
        eventPatternJson.includes('IoTSiteWise') ||
        eventPatternJson.includes('SiteWise')) {
        return true;
      }
    }

    // Check if the rule references IoT SiteWise in its configuration
    return ruleJson.includes('iotsitewise') ||
      ruleJson.includes('IoTSiteWise') ||
      ruleJson.includes('SiteWise');
  }


  /**
   * Check if a Lambda function is for processing logs
   */
  private isLogProcessingFunction(resource: CloudFormationResource): boolean {
    const functionName = resource.Properties?.FunctionName || '';
    const code = resource.Properties?.Code?.ZipFile || '';
    const functionJson = JSON.stringify(resource);

    // Check if the function name indicates it's for log processing
    if (typeof functionName === 'string' && (
      functionName.includes('LogProcessor') ||
      functionName.includes('log-processor') ||
      functionName.includes('LogMonitor') ||
      functionName.includes('log-monitor')
    )) {
      return true;
    }

    // Check if the function code includes log processing logic
    if (typeof code === 'string' && (
      code.includes('CloudWatchLogs') ||
      code.includes('logs.amazonaws.com') ||
      code.includes('LogGroup')
    )) {
      return true;
    }

    // Check if the function references CloudWatch Logs in its configuration
    return functionJson.includes('logs:') ||
      functionJson.includes('CloudWatchLogs') ||
      functionJson.includes('LogGroup');
  }

  /**
   * Check if an SNS Topic is for notifications
   */
  private isNotificationTopic(resource: CloudFormationResource): boolean {
    const topicName = resource.Properties?.TopicName || '';
    const topicJson = JSON.stringify(resource);

    // Check if the topic name indicates it's for notifications
    if (typeof topicName === 'string' && (
      topicName.includes('Notification') ||
      topicName.includes('notification') ||
      topicName.includes('Alert') ||
      topicName.includes('alert')
    )) {
      return true;
    }

    // Check if the topic references CloudWatch or IoT SiteWise in its configuration
    return topicJson.includes('CloudWatch') ||
      topicJson.includes('cloudwatch') ||
      topicJson.includes('Alarm') ||
      topicJson.includes('alarm') ||
      topicJson.includes('IoTSiteWise') ||
      topicJson.includes('iotsitewise') ||
      topicJson.includes('SiteWise');
  }

  /**
   * Check if a CloudWatch Dashboard is for IoT SiteWise
   */
  private isDashboardForIoTSiteWise(resource: CloudFormationResource): boolean {
    const dashboardName = resource.Properties?.DashboardName || '';
    const dashboardBody = resource.Properties?.DashboardBody || '';

    // Check if the dashboard name indicates it's for IoT SiteWise
    if (typeof dashboardName === 'string' && (
      dashboardName.includes('IoTSiteWise') ||
      dashboardName.includes('iot-sitewise') ||
      dashboardName.includes('SiteWise')
    )) {
      return true;
    }

    // Check if the dashboard body includes IoT SiteWise widgets
    if (typeof dashboardBody === 'string' && (
      dashboardBody.includes('IoTSiteWise') ||
      dashboardBody.includes('iotsitewise') ||
      dashboardBody.includes('SiteWise') ||
      dashboardBody.includes('AWS/IoTSiteWise')
    )) {
      return true;
    }

    return false;
  }


  /**
   * Check if a resource has tags indicating ownership
   * This helps identify who is responsible for monitoring this resource
   */
  private hasOwnershipTags(resource: CloudFormationResource): boolean {
    const tags = resource.Properties?.Tags;

    // If no tags, return false
    if (!tags || !Array.isArray(tags)) {
      return false;
    }

    // Look for ownership-related tags
    for (const tag of tags) {
      // Skip if tag is malformed
      if (!tag.Key || typeof tag.Key !== 'string') {
        continue;
      }

      const key = tag.Key.toLowerCase();

      // Check for common ownership tag keys
      if (key === 'owner' ||
        key === 'team' ||
        key === 'contact' ||
        key === 'responsible' ||
        key === 'administrator' ||
        key === 'admin' ||
        key === 'notification-contact' ||
        key === 'monitoring-owner') {
        return true;
      }

      // Check for common ownership tag values if there's a value
      if (tag.Value && typeof tag.Value === 'string') {
        const value = tag.Value.toLowerCase();

        if (value.includes('admin') ||
          value.includes('monitor') ||
          value.includes('operations') ||
          value.includes('notification')) {
          return true;
        }
      }
    }

    return false;
  }
}

export default new IoT031Rule();
