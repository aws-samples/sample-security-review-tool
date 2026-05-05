import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift004Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-004',
      'HIGH',
      'Redshift cluster is publicly accessible',
      ['AWS::Redshift::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
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
        `Configure PubliclyAccessible property to false.`
      );
    }

    if (resource.Type === 'AWS::Redshift::Cluster') {
      return this.evaluateCluster(resource, stackName);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const publiclyAccessible = resource.Properties.PubliclyAccessible;

    // If PubliclyAccessible is not specified, it defaults to true in some cases
    // We should be explicit and require it to be set to false
    if (publiclyAccessible === undefined || publiclyAccessible === null) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Explicitly set PubliclyAccessible to false to ensure the cluster is not publicly accessible.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof publiclyAccessible === 'object') {
      // Could be a Ref, GetAtt, or other intrinsic function
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set PubliclyAccessible to an explicit boolean value (false) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Check if explicitly set to true
    if (publiclyAccessible === true || publiclyAccessible === 'true') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set PubliclyAccessible to false to prevent public internet access to the cluster.`
      );
    }

    // Check if set to false (compliant)
    if (publiclyAccessible === false || publiclyAccessible === 'false') {
      return null; // Compliant
    }

    // For any other unexpected value, flag as non-compliant
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Set PubliclyAccessible to false (current value: ${publiclyAccessible}).`
    );
  }
}

export default new Redshift004Rule();