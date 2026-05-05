import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEmr002Rule extends BaseTerraformRule {
  constructor() {
    super('EMR-002', 'HIGH', 'EMR cluster does not have S3 logging configured', ['aws_emr_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_emr_cluster') {
      const logUri = resource.values?.log_uri;
      if (!logUri || !logUri.startsWith('s3://')) {
        return this.createScanResult(resource, projectName, this.description, 'Set log_uri to an S3 path (e.g., "s3://bucket-name/logs/") to enable cluster logging.');
      }
    }

    return null;
  }
}

export default new TfEmr002Rule();
