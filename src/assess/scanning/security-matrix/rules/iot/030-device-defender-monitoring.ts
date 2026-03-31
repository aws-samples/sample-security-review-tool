import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * IoT30 Rule: Ensure IoT Device Defender security profiles are configured for continuous monitoring.
 * 
 * Documentation: "IoT Core IoT30: Ensure IoT Device Defender security profiles are configured for continuous monitoring.
 * Configure security profiles to monitor device behavior and detect anomalies. Set up alerts for security violations
 * and ensure proper response procedures are in place for detected threats.
 * See https://docs.aws.amazon.com/iot-device-defender/latest/developerguide/device-defender-detect.html"
 * 
 * This rule checks if IoT resources have proper Device Defender security profiles configured.
 */
export class IoT030Rule extends BaseRule {
  constructor() {
    super(
      'IOT-030',
      'HIGH',
      'IoT Device Defender security monitoring not properly configured',
      [
        'AWS::IoT::SecurityProfile',
        'AWS::IoT::Thing',
        'AWS::IoT::ThingGroup',
        'AWS::IoT::Policy',
        'AWS::IoT::TopicRule'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip non-IoT resources
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    // Skip resources with no properties
    if (!resource.Properties) {
      return null;
    }

    // Handle specific resource types
    switch (resource.Type) {
      case 'AWS::IoT::SecurityProfile':
        return this.evaluateSecurityProfile(resource, stackName);

      case 'AWS::IoT::Thing':
      case 'AWS::IoT::ThingGroup':
        return this.evaluateThingOrGroup(resource, stackName, allResources);

      case 'AWS::IoT::Policy':
        return this.evaluateIoTPolicy(resource, stackName, allResources);

      case 'AWS::IoT::TopicRule':
        return this.evaluateTopicRule(resource, stackName, allResources);
    }

    return null;
  }

  /**
   * Evaluate IoT Security Profile for proper monitoring configuration
   */
  private evaluateSecurityProfile(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const issues = [];

    // Check if behaviors are defined
    const behaviors = resource.Properties?.Behaviors;
    if (!behaviors || !Array.isArray(behaviors) || behaviors.length === 0) {
      issues.push('no security behaviors defined');
    } else {
      // Check for essential security behaviors
      const behaviorNames = behaviors.map(b => b.Name || '').join(' ').toLowerCase();

      if (!behaviorNames.includes('authorization') && !behaviorNames.includes('auth')) {
        issues.push('missing authorization failure monitoring');
      }

      if (!behaviorNames.includes('connection') && !behaviorNames.includes('connect')) {
        issues.push('missing connection monitoring');
      }

      if (!behaviorNames.includes('message') && !behaviorNames.includes('data')) {
        issues.push('missing message/data transfer monitoring');
      }
    }

    // Check if alert targets are configured
    const alertTargets = resource.Properties?.AlertTargets;
    if (!alertTargets || Object.keys(alertTargets).length === 0) {
      issues.push('no alert targets configured');
    }

    // Check if additional metrics are enabled
    const additionalMetricsToRetain = resource.Properties?.AdditionalMetricsToRetain;
    if (!additionalMetricsToRetain || !Array.isArray(additionalMetricsToRetain) || additionalMetricsToRetain.length === 0) {
      issues.push('no additional metrics configured for retention');
    }

    if (issues.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (${issues[0]})`,
        `Configure comprehensive security behaviors and alert targets.`
      );
    }

    return null;
  }

  /**
   * Evaluate IoT Thing or Thing Group for Device Defender association
   */
  private evaluateThingOrGroup(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (cannot verify security profile association)`,
        `Use !Ref to reference security profiles defined in template or ensure external security profiles target this resource.`
      );
    }

    const resolver = new CloudFormationResolver(allResources);
    const securityProfiles = resolver.getResourcesByType('AWS::IoT::SecurityProfile');

    const hasSecurityProfile = securityProfiles.some(profile =>
      this.securityProfileTargetsResource(profile, resource, resolver)
    );

    if (!hasSecurityProfile) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no security profile targets ${resource.LogicalId})`,
        `Add security profile with Targets property referencing this resource.`
      );
    }

    return null;
  }

  /**
   * Evaluate IoT Policy for Device Defender permissions
   */
  private evaluateIoTPolicy(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const policyDocument = resource.Properties?.PolicyDocument;

    if (!policyDocument) {
      return null;
    }

    const policyStr = JSON.stringify(policyDocument).toLowerCase();

    // Check if policy allows Device Defender metrics publishing
    const hasDefenderPermissions =
      policyStr.includes('iot:publish') &&
      (policyStr.includes('$aws/things/') || policyStr.includes('device-defender'));

    if (!hasDefenderPermissions) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (policy missing Device Defender permissions)`,
        `Add permissions for Device Defender metrics publishing.`
      );
    }

    return null;
  }

  /**
   * Evaluate Topic Rule for Device Defender integration
   */
  private evaluateTopicRule(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const topicRulePayload = resource.Properties?.TopicRulePayload;

    if (!topicRulePayload) {
      return null;
    }

    const sql = topicRulePayload.Sql || '';
    const actions = topicRulePayload.Actions || [];

    // Check if this is a security-related topic rule
    const isSecurityRule =
      sql.toLowerCase().includes('security') ||
      sql.toLowerCase().includes('violation') ||
      sql.toLowerCase().includes('alert') ||
      sql.toLowerCase().includes('defender');

    if (isSecurityRule) {
      // Check if actions are configured for security alerts
      const hasAlertActions = actions.some((action: any) =>
        action.sns || action.lambda || action.cloudwatchAlarm || action.iotEvents
      );

      if (!hasAlertActions) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (security topic rule missing alert actions)`,
          `Configure SNS, Lambda, or CloudWatch alarm actions for security alerts.`
        );
      }
    }

    return null;
  }

  /**
   * Check if a security profile targets a specific resource
   */
  private securityProfileTargetsResource(securityProfile: CloudFormationResource, targetResource: CloudFormationResource, resolver: CloudFormationResolver): boolean {
    const targets = securityProfile.Properties?.Targets;

    if (!targets || !Array.isArray(targets)) {
      return false;
    }

    return targets.some(target => {
      const resolved = resolver.resolve(target);
      return resolved.referencedResources.includes(targetResource.LogicalId) ||
        resolved.value === targetResource.LogicalId;
    });
  }
}

export default new IoT030Rule();
