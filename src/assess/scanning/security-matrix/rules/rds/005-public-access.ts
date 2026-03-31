import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds005Rule extends BaseRule {
  constructor() {
    super(
      'RDS-005',
      'HIGH',
      'Database has public access enabled',
      ['AWS::RDS::DBInstance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBInstance') {
      const publiclyAccessible = resource.Properties?.PubliclyAccessible;

      if (publiclyAccessible === true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set PubliclyAccessible to false and deploy in a private subnet.`
        );
      }
    }

    return null;
  }
}

export default new Rds005Rule();
