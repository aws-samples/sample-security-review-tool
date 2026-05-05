import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MS8 Rule: Implement a Cross Origin Resource Sharing (CORS) in every AWS Elemental MediaStore service.
 * 
 * CORS should be used to explicitly allow and/or restrict access. If CORS is not implemented, 
 * unintended web sites or clients may be able to access customer content.
 */
export class MEDIASTORE008Rule extends BaseRule {
  constructor() {
    super(
      'MEDIASTORE-008',
      'HIGH',
      'MediaStore container must implement CORS policy to explicitly allow/restrict access',
      ['AWS::MediaStore::Container']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaStore::Container') {
      return null;
    }

    const properties = resource.Properties || {};
    
    if (!properties.CorsPolicy) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add CorsPolicy array with AllowedOrigins restricted to legitimate domains. Analyze the application context to identify which origins need access, then configure appropriate CORS settings including AllowedMethods and headers.'
      );
    }

    return null;
  }
}

export default new MEDIASTORE008Rule();