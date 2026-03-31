import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS16 Rule: Ensure that audit logs are enabled for the control plane.
 * 
 * Documentation: "You must enable each log type individually to send logs for your cluster.
 * CloudWatch Logs ingestion, archive storage, and data scanning rates apply to enabled control plane logs.
 * Auditing tools: - kubeaudit - MKIT"
 * 
 * Note: This rule is partially covered by Checkov rule CKV_AWS_67 which checks if EKS cluster has logging enabled.
 * This rule specifically focuses on audit logs.
 */
export class EKS016Rule extends BaseRule {
  constructor() {
    super(
      'EKS-016',
      'HIGH',
      'EKS cluster does not have audit logs enabled for the control plane',
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
        `Configure Logging property with ClusterLogging enabled for audit logs.`
      );
    }

    const clusterLogging = logging.ClusterLogging;
    if (!clusterLogging || !Array.isArray(clusterLogging) || clusterLogging.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure ClusterLogging with enabled log types including audit logs.`
      );
    }

    // Check if audit logging is specifically enabled
    let auditLogsEnabled = false;

    for (const config of clusterLogging) {
      if (config.Enabled === true && config.Types && Array.isArray(config.Types)) {
        if (config.Types.includes('audit')) {
          auditLogsEnabled = true;
          break;
        }
      }
    }

    if (!auditLogsEnabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable audit logs by adding 'audit' to the Types array in an enabled ClusterLogging configuration.`
      );
    }

    // Check if logs are being sent to CloudWatch Logs
    // Note: In EKS CloudFormation, enabling logging automatically sends logs to CloudWatch
    // so there's no separate property to check for the destination

    return null;
  }
}

export default new EKS016Rule();
