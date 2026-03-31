import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EMR2 Rule: Is cluster logging to S3 enabled?
 * 
 * Documentation: "Solution cluster log files must be periodically archived and uploaded to S3 
 * in order to keep the logging data for historical purposes or to track and analyze the EMR clusters behavior."
 */
export class EMR002Rule extends BaseRule {
  constructor() {
    super(
      'EMR-002',
      'HIGH',
      'EMR cluster does not have S3 logging configured',
      ['AWS::EMR::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::EMR::Cluster') {
      return null;
    }

    // EMR2: Is cluster logging to S3 enabled?
    const logUri = resource.Properties?.LogUri;
    
    if (!logUri || !logUri.startsWith('s3://')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add LogUri property with S3 path (e.g., 's3://<bucket-name>/logs/') to enable cluster logging.`
      );
    }

    // S3 logging is configured - EMR2 requirement satisfied
    return null;
  }
}

export default new EMR002Rule();
