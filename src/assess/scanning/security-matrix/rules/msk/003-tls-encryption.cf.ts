import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK3 Rule: For communication between the brokers, I confirm that I'm using the default of TLS.
 * 
 * Documentation: "Amazon MSK uses TLS 1.2. By default, it encrypts data in transit between the brokers 
 * of your MSK cluster. You can override this default at the time you create the cluster."
 */
export class MSK003Rule extends BaseRule {
  constructor() {
    super(
      'MSK-003',
      'HIGH',
      'MSK cluster is not configured with TLS encryption between brokers',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    const encryptionInfo = resource.Properties?.EncryptionInfo;
    
    if (!encryptionInfo) {
      // Default is TLS enabled, so no explicit configuration is acceptable
      return null;
    }

    // Check EncryptionInTransit configuration
    const encryptionInTransit = encryptionInfo.EncryptionInTransit;
    
    if (!encryptionInTransit) {
      // Default is TLS enabled, so no explicit configuration is acceptable
      return null;
    }

    // Check if TLS is explicitly disabled
    const inCluster = encryptionInTransit.InCluster;
    
    if (inCluster === false) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Remove EncryptionInfo.EncryptionInTransit.InCluster: false or set it to true to enable TLS encryption between brokers.`
      );
    }

    // TLS encryption is enabled (default or explicitly set to true) - MSK3 requirement satisfied
    return null;
  }
}

export default new MSK003Rule();