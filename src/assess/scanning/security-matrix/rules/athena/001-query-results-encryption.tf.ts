import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAth001Rule extends BaseTerraformRule {
  constructor() {
    super('ATH-001', 'HIGH', 'Athena workgroup does not have encryption enabled for query results', ['aws_athena_workgroup']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_athena_workgroup') {
      const encryptionConfig = resource.values?.configuration?.result_configuration?.encryption_configuration;

      if (!encryptionConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add configuration.result_configuration.encryption_configuration with encryption_option (SSE_S3, SSE_KMS, or CSE_KMS).');
      }

      const encryptionOption = encryptionConfig.encryption_option;
      const validOptions = ['SSE_S3', 'SSE_KMS', 'CSE_KMS'];

      if (!encryptionOption || !validOptions.includes(encryptionOption)) {
        return this.createScanResult(resource, projectName, this.description, 'Set encryption_option to "SSE_S3", "SSE_KMS", or "CSE_KMS".');
      }

      if (['SSE_KMS', 'CSE_KMS'].includes(encryptionOption) && !encryptionConfig.kms_key_arn) {
        return this.createScanResult(resource, projectName, this.description, 'Specify kms_key_arn when using ' + encryptionOption + ' encryption.');
      }
    }

    return null;
  }
}

export default new TfAth001Rule();
