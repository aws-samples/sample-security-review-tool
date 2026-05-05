import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEfs007Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EFS-007',
      'HIGH',
      'EFS file system does not have automatic backups configured',
      ['aws_efs_file_system']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const hasBackupPolicy = this.hasBackupPolicyEnabled(resource);

    if (hasBackupPolicy) {
      return null;
    }

    const isIncludedInBackup = this.isIncludedInBackupSelection(resource, allResources);

    if (isIncludedInBackup) {
      return null;
    }

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      `Enable automatic backups by adding a lifecycle_policy with transition_to_primary_storage_class, or include this EFS in an AWS Backup plan using aws_backup_selection.`
    );
  }

  private hasBackupPolicyEnabled(resource: TerraformResource): boolean {
    const backupPolicy = resource.values?.backup_policy;
    if (!backupPolicy) return false;
    return backupPolicy.status === 'ENABLED';
  }

  private isIncludedInBackupSelection(resource: TerraformResource, allResources: TerraformResource[]): boolean {
    const backupSelections = allResources.filter(r => r.type === 'aws_backup_selection');

    for (const selection of backupSelections) {
      const resources = selection.values?.resources;
      if (!resources || !Array.isArray(resources)) continue;

      for (const res of resources) {
        if (typeof res === 'string') {
          if (res === '*' || res.includes('elasticfilesystem') || res.includes('efs')) {
            return true;
          }
        }
      }
    }

    return false;
  }
}

export default new TfEfs007Rule();
