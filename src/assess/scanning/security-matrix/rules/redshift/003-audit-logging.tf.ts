import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-003',
      'HIGH',
      'Redshift cluster does not have audit logging enabled',
      ['aws_redshift_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const logging = resource.values?.logging;

    if (!logging) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure the logging block with enable = true and a bucket_name to store audit logs.`
      );
    }

    if (logging.enable !== true) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set logging.enable to true to enable audit logging.`
      );
    }

    if (!logging.bucket_name) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add bucket_name to the logging block to specify where audit logs are stored.`
      );
    }

    return null;
  }
}

export default new TfRedshift003Rule();
