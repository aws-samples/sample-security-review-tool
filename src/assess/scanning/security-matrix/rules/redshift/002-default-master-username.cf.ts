import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift002Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-002',
      'HIGH',
      'Redshift cluster is using the default master username "awsuser"',
      ['AWS::Redshift::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify a custom MasterUsername other than "awsuser".`
      );
    }

    const masterUsername = resource.Properties.MasterUsername;

    // If MasterUsername is missing, it will default to "awsuser"
    if (!masterUsername) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify a custom MasterUsername other than "awsuser".`
      );
    }

    // // If MasterUsername is a reference, consider it compliant
    // if (typeof masterUsername === 'object') {
    //   return null;
    // }

    // If MasterUsername is explicitly set to "awsuser", it's non-compliant
    if (masterUsername === 'awsuser') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Change the MasterUsername to a value other than "awsuser".`
      );
    }

    // Any other value is compliant
    return null;
  }
}

export default new Redshift002Rule();
