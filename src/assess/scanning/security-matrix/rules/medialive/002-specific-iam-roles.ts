import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ML2 Rule: Use specific IAM roles for AWS Elemental MediaLive services.
 * 
 * AWS MediaLive services should always have a 1:1 relationship to IAM roles to ensure 
 * different users have the fewest privileges they need. IAM roles should not be shared 
 * or reused among MediaLive instantiations.
 */
export class MEDIALIVE002Rule extends BaseRule {
  constructor() {
    super(
      'MEDIALIVE-002',
      'HIGH',
      'MediaLive channel must specify a dedicated IAM role',
      ['AWS::MediaLive::Channel']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type !== 'AWS::MediaLive::Channel') {
      return null;
    }

    const properties = resource.Properties || {};
    const roleArn = properties.RoleArn;
    
    if (!roleArn) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add "RoleArn": "arn:aws:iam::ACCOUNT-ID:role/MediaLive-${resource.LogicalId}-Role" with a dedicated IAM role`
      );
    }

    // Check for role sharing across MediaLive channels
    if (allResources) {
      const otherChannels = allResources.filter(r => 
        r.Type === 'AWS::MediaLive::Channel' && 
        r.LogicalId !== resource.LogicalId &&
        r.Properties?.RoleArn === roleArn
      );

      if (otherChannels.length > 0) {
        return this.createScanResult(
          resource,
          stackName,
          'MediaLive channel is sharing an IAM role with another channel - each channel should have a unique role',
          `Create dedicated IAM role: "RoleArn": "arn:aws:iam::ACCOUNT-ID:role/MediaLive-${resource.LogicalId}-Role"`
        );
      }
    }

    return null;
  }
}

export default new MEDIALIVE002Rule();