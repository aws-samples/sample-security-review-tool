import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS2 Rule: Ensure that control plane logs are enabled for EKS clusters.
 * 
 * Documentation: "A solutions cluster(s) must have control plane logs enabled in order to publish API, 
 * audit, controller manager, scheduler or authenticator logs to AWS CloudWatch Logs."
 * 
 * Note: This rule is partially covered by Checkov rule CKV_AWS_67 which checks if EKS cluster has logging enabled.
 * This rule adds additional checks for specific log types that should be enabled.
 */
export class EKS002Rule extends BaseRule {
  constructor() {
    super(
      'EKS-002',
      'HIGH',
      'EKS cluster does not have control plane logs enabled',
      ['AWS::EKS::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::EKS::Cluster') {
      return null;
    }

    const logging = resource.Properties?.Logging;
    if (!logging) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure Logging property with ClusterLogging enabled for all log types.`
      );
    }

    // Handle CloudFormation intrinsic functions for Logging
    if (typeof logging === 'object') {
      if (!logging.ClusterLogging) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set Logging to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }
    }

    const clusterLogging = logging.ClusterLogging;
    if (!clusterLogging || !Array.isArray(clusterLogging) || clusterLogging.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure ClusterLogging with enabled log types.`
      );
    }

    const requiredLogTypes = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'];
    const enabledLogTypes: string[] = [];

    for (const config of clusterLogging) {
      if (config.Enabled === true && config.Types && Array.isArray(config.Types)) {
        enabledLogTypes.push(...config.Types);
      }
    }

    const missingLogTypes = requiredLogTypes.filter(type => !enabledLogTypes.includes(type));

    if (missingLogTypes.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (missing log types: ${missingLogTypes.join(',')})`,
        `Enable all required log types: api, audit, authenticator, controllerManager, and scheduler.`
        );
    }

    return null;
  }
}

export default new EKS002Rule();
