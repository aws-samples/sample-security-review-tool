import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MS14 Rule: Implement a deny-by-default container policy for secure data transport and cross-account access.
 * 
 * Do not leave containers vulnerable to unintended access.
 */
export class MEDIASTORE014Rule extends BaseRule {
  constructor() {
    super(
      'MEDIASTORE-014',
      'HIGH',
      'MediaStore container must implement deny-by-default policy to prevent unintended access',
      ['AWS::MediaStore::Container']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaStore::Container') {
      return null;
    }

    const properties = resource.Properties || {};
    const policy = properties.Policy;
    
    if (!policy) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add "Policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}, {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::ACCOUNT-ID:root"}, "Action": "mediastore:GetObject", "Resource": "arn:aws:mediastore:*:*:container/*/", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}'
      );
    }

    const policyStr = typeof policy === 'string' ? policy : JSON.stringify(policy);
    const hasExplicitDeny = policyStr.includes('"Effect": "Deny"') || policyStr.includes('"Effect":"Deny"');
    const hasSecureTransport = policyStr.includes('aws:SecureTransport');
    
    if (!hasExplicitDeny || !hasSecureTransport) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add deny statement to existing policy: {"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}'
      );
    }

    return null;
  }
}

export default new MEDIASTORE014Rule();