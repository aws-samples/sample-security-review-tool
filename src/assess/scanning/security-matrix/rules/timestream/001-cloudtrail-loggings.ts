import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Timestream001Rule extends BaseRule {
  constructor() {
    super(
      'TIMESTREAM-001',
      'HIGH',
      'Timestream resources deployed without CloudTrail logging configured',
      ['AWS::Timestream::Database']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    return this.evaluateCloudTrailPresence(resource, stackName, allResources || []);
  }

  private evaluateCloudTrailPresence(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // Look for CloudTrail trails in the same template
    const cloudTrails = this.findCloudTrails(allResources);

    if (cloudTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Create an AWS::CloudTrail::Trail resource in the template to log Timestream API calls, or ensure CloudTrail is configured externally for this account.`
      );
    }

    // Check if any of the trails are properly configured for logging
    const trailValidation = this.hasValidCloudTrail(cloudTrails);

    if (!trailValidation.isValid) {
      const actionMessage = trailValidation.reason || 'Ensure CloudTrail trail has IsLogging enabled and includes management events to capture Timestream API calls.';

      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `${actionMessage}`
      );
    }

    // CloudTrail is present and properly configured
    return null;
  }

  private findCloudTrails(allResources: CloudFormationResource[]): CloudFormationResource[] {
    return allResources.filter(resource => resource.Type === 'AWS::CloudTrail::Trail');
  }

  private hasValidCloudTrail(cloudTrails: CloudFormationResource[]): { isValid: boolean; reason?: string } {
    for (const trail of cloudTrails) {
      const validationResult = this.isValidCloudTrail(trail);
      if (validationResult === true) {
        return { isValid: true };
      }
      if (typeof validationResult === 'string') {
        return { isValid: false, reason: validationResult };
      }
    }
    return { isValid: false };
  }

  private isValidCloudTrail(trail: CloudFormationResource): boolean | string {
    // Check if trail has properties
    if (!trail.Properties) {
      return false;
    }

    // Check if logging is enabled (IsLogging property)
    const isLogging = trail.Properties.IsLogging;

    // If IsLogging is explicitly set to false, trail is not valid
    if (isLogging === false || isLogging === 'false') {
      return false;
    }

    // Handle CloudFormation intrinsic functions for IsLogging
    if (typeof isLogging === 'object') {
      // We can't determine the actual value at scan time, so flag as non-compliant
      return 'Set CloudTrail IsLogging property to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.';
    }

    // Check if trail has S3 bucket configured (name doesn't matter, just that it exists)
    const s3BucketName = trail.Properties.S3BucketName;
    if (!s3BucketName) {
      return false;
    }

    // Trail appears to be valid if it has logging enabled and S3 bucket
    return true;
  }
}

export default new Timestream001Rule();