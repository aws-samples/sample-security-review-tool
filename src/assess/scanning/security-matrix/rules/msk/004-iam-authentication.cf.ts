import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MSK4 Rule: I confirm that I'm using IAM as the authentication method.
 * 
 * Documentation: "MSK offers several ways of authentication, such as IAM, client TLS and username/password. 
 * IAM is the recommended approach, but it does require additional configuration on the clients and it's not 
 * supported in Lambda at this time."
 */
export class MSK004Rule extends BaseRule {
  constructor() {
    super(
      'MSK-004',
      'HIGH',
      'MSK cluster is not configured with IAM authentication',
      ['AWS::MSK::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MSK::Cluster') {
      return null;
    }

    const clientAuthentication = resource.Properties?.ClientAuthentication;
    
    if (!clientAuthentication) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add ClientAuthentication.Sasl.Iam.Enabled: true to enable IAM authentication.`
      );
    }

    // Check for IAM authentication
    const iamEnabled = clientAuthentication.Sasl?.Iam?.Enabled;
    
    if (iamEnabled !== true) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set ClientAuthentication.Sasl.Iam.Enabled to true to enable IAM authentication.`
      );
    }

    // IAM authentication is enabled - MSK4 requirement satisfied
    return null;
  }
}

export default new MSK004Rule();