import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsxN003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-N003',
      'HIGH',
      'FSx ONTAP storage virtual machine does not restrict SSH private key access',
      ['aws_fsx_ontap_storage_virtual_machine']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const activeDirectoryConfiguration = resource.values?.active_directory_configuration;

    if (!activeDirectoryConfiguration) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure active_directory_configuration to manage authentication and restrict SSH private key access.`
      );
    }

    const selfManagedActiveDirectory = activeDirectoryConfiguration.self_managed_active_directory_configuration;
    if (selfManagedActiveDirectory) {
      const password = selfManagedActiveDirectory.password;
      if (typeof password === 'string' && password.length > 0 && !password.includes('var.') && !password.includes('data.')) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Do not hardcode passwords in configuration. Use a variable or data source referencing AWS Secrets Manager.`
        );
      }
    }

    return null;
  }
}

export default new TfFsxN003Rule();
