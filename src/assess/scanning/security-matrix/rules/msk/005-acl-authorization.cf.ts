import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK5 Rule: If the solution creates topics, is authorization with ACLs being used?
 * 
 * Documentation: "Apache Kafka has a pluggable authorizer and ships with an out-of-box authorizer implementation that uses Apache ZooKeeper to store all ACLs. 
 * By default in MSK, if you don't explicitly set ACLs on a resource, all principals can access this resource. If you enable ACLs on a resource, only the authorized principals can access it."
 */
export class MSK005Rule extends BaseRule {
  constructor() {
    super(
      'MSK-005',
      'HIGH',
      'MSK cluster does not have proper authentication configured for ACL authorization',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    // Check if ClientAuthentication is configured (required for ACLs)
    const clientAuthentication = resource.Properties?.ClientAuthentication;
    if (!clientAuthentication) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add ClientAuthentication.Sasl.Iam.Enabled: true to enable IAM authentication required for ACL authorization.`
      );
    }

    // Check if SASL authentication is configured
    const sasl = clientAuthentication.Sasl;
    if (!sasl) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add ClientAuthentication.Sasl.Iam.Enabled: true to enable SASL authentication for ACL support.`
      );
    }

    // Check if IAM or SCRAM authentication is enabled (both support ACLs)
    const iamEnabled = sasl.Iam?.Enabled === true;
    const scramEnabled = sasl.Scram?.Enabled === true;

    if (!iamEnabled && !scramEnabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set ClientAuthentication.Sasl.Iam.Enabled to true to enable IAM authentication for ACL authorization.`
      );
    }

    // If authentication is properly configured, ACLs can be used
    return null;
  }
}

export default new MSK005Rule();