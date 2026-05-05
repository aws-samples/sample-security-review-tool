import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * IoT-020 Rule: Use IoT Device Defender to audit IoT device fleet
 * 
 * Documentation: AWS IoT Device Defender helps you audit the configuration of your IoT devices,
 * detect abnormal behaviors, and mitigate security risks. This rule verifies that 
 * Device Defender audit configurations are in place for IoT devices and device fleets.
 * 
 * The rule checks for:
 * - IoT Security Profiles that define expected behavior and metrics
 * - Fleet Indexing to enable fleet-wide searches and aggregations
 * - Custom audit configurations through Lambda functions or custom resources
 * 
 * See https://docs.aws.amazon.com/iot/latest/developerguide/device-defender.html
 */
export class IoT020Rule extends BaseRule {
  constructor() {
    super(
      'IOT-020',
      'HIGH',
      'IoT Device Defender audit configuration missing for device fleet',
      [
        'AWS::IoT::Thing',
        'AWS::IoT::ThingGroup'
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
        `${this.description} (cannot verify Device Defender configuration)`,
        `Configure IoT Device Defender audit checks for device fleet.`
      );
    }

    const resolver = new CloudFormationResolver(allResources);

    // Check for Device Defender audit configurations
    if (!this.hasDeviceDefenderAudit(resolver)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no audit configuration found)`,
        `Enable IoT Device Defender audit checks and configure fleet indexing.`
      );
    }

    return null;
  }

  private hasDeviceDefenderAudit(resolver: CloudFormationResolver): boolean {
    // Check for security profiles (audit configurations)
    const securityProfiles = resolver.getResourcesByType('AWS::IoT::SecurityProfile');

    // Check for fleet indexing configuration
    const fleetMetrics = resolver.getResourcesByType('AWS::IoT::FleetMetric');

    // Check for audit configurations in custom resources or Lambda functions
    const customResources = resolver.getResourcesByType('AWS::CloudFormation::CustomResource');
    const lambdaFunctions = resolver.getResourcesByType('AWS::Lambda::Function');

    const hasAuditLambda = lambdaFunctions.some(lambda => {
      const code = JSON.stringify(lambda.Properties?.Code || {}).toLowerCase();
      return code.includes('device-defender') || code.includes('audit') || code.includes('fleet');
    });

    return securityProfiles.length > 0 || fleetMetrics.length > 0 || hasAuditLambda;
  }
}

export default new IoT020Rule();
