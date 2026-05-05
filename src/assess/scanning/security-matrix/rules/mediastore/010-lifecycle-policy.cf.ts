import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MS10 Rule: Implement object lifecycle policies for AWS Elemental MediaStore containers.
 * 
 * For each container, you should create an object lifecycle policy that governs how long 
 * objects should be stored in the container.
 */
export class MEDIASTORE010Rule extends BaseRule {
  constructor() {
    super(
      'MEDIASTORE-010',
      'HIGH',
      'MediaStore container must implement object lifecycle policy to govern object storage duration',
      ['AWS::MediaStore::Container']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaStore::Container') {
      return null;
    }

    const properties = resource.Properties || {};
    
    if (!properties.LifecyclePolicy) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add "LifecyclePolicy": {"rules":[{"definition":{"path":[{"wildcard":"*"}],"days_since_create":[{"numeric":[">"30]}]},"action":"EXPIRE"}]}'
      );
    }

    return null;
  }
}

export default new MEDIASTORE010Rule();