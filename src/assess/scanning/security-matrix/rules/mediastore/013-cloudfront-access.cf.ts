import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * MS13 Rule: Restrict AWS CloudFront access to an AWS Elemental MediaStore origin.
 * 
 * Use either a CloudFront Origin Access Control (OAC) or a resource policy that grants 
 * use of shared secrets.
 */
export class MEDIASTORE013Rule extends BaseRule {
  constructor() {
    super(
      'MEDIASTORE-013',
      'HIGH',
      'MediaStore container must have resource policy to restrict CloudFront access',
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
        'Add "Policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "mediastore:GetObject", "Resource": "arn:aws:mediastore:*:*:container/*/", "Condition": {"StringEquals": {"AWS:SourceArn": "arn:aws:cloudfront::*:distribution/*"}}}]}'
      );
    }

    const policyStr = typeof policy === 'string' ? policy : JSON.stringify(policy);
    if (!policyStr.includes('cloudfront') && !policyStr.includes('SourceArn')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add CloudFront statement to existing policy: {"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "mediastore:GetObject", "Resource": "arn:aws:mediastore:*:*:container/*/", "Condition": {"StringEquals": {"AWS:SourceArn": "arn:aws:cloudfront::*:distribution/*"}}}'
      );
    }

    return null;
  }
}

export default new MEDIASTORE013Rule();