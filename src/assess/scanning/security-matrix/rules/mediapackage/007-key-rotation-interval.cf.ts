import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MP7 Rule: Implement a Key Rotation Interval of at least 300 seconds on origin endpoints.
 * 
 * Rotating keys frequently reduces unintended MediaPackage resource usage.
 */
export class MEDIAPACKAGE007Rule extends BaseRule {
  constructor() {
    super(
      'MEDIAPACKAGE-007',
      'HIGH',
      'MediaPackage origin endpoint with encryption must specify KeyRotationIntervalSeconds of at least 300',
      ['AWS::MediaPackage::OriginEndpoint']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaPackage::OriginEndpoint') {
      return null;
    }

    const properties = resource.Properties || {};
    const hlsPackage = properties.HlsPackage;
    const dashPackage = properties.DashPackage;
    const mssPackage = properties.MssPackage;
    const cmafPackage = properties.CmafPackage;
    
    const packages = [hlsPackage, dashPackage, mssPackage, cmafPackage].filter(Boolean);
    
    for (const pkg of packages) {
      if (pkg.Encryption) {
        const keyRotationIntervalSeconds = pkg.Encryption.KeyRotationIntervalSeconds;
        
        if (keyRotationIntervalSeconds === undefined) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            'Add "KeyRotationIntervalSeconds": 300 to the Encryption object'
          );
        } else if (keyRotationIntervalSeconds < 300) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            'Change "KeyRotationIntervalSeconds": ' + keyRotationIntervalSeconds + ' to "KeyRotationIntervalSeconds": 300'
          );
        }
      }
    }

    return null;
  }
}

export default new MEDIAPACKAGE007Rule();