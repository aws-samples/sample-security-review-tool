import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MP3 Rule: Restrict origin endpoints to either CDN authorization or IPv4 address ranges.
 * 
 * MediaPackage endpoints should not be publicly available and should be locked down using 
 * CDN authorization (preferred) and/or via restricting source IP access.
 */
export class MEDIAPACKAGE003Rule extends BaseRule {
  constructor() {
    super(
      'MEDIAPACKAGE-003',
      'HIGH',
      'MediaPackage origin endpoint must restrict access using CDN authorization or IP whitelisting',
      ['AWS::MediaPackage::OriginEndpoint']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaPackage::OriginEndpoint') {
      return null;
    }

    const properties = resource.Properties || {};
    const authorization = properties.Authorization;
    const whitelist = properties.Whitelist;
    
    if (!authorization && !whitelist) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add "Authorization": {"CdnIdentifierSecret": "arn:aws:secretsmanager:region:account:secret:secret-name", "SecretsRoleArn": "arn:aws:iam::account:role/MediaPackageSecretsRole"}'
      );
    }

    if (whitelist && Array.isArray(whitelist) && whitelist.includes('0.0.0.0/0')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Replace "0.0.0.0/0" with specific CIDR blocks like "192.168.1.0/24" instead of allowing unrestricted access'
      );
    }

    return null;
  }
}

export default new MEDIAPACKAGE003Rule();