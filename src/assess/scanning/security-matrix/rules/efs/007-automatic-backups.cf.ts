import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * EFS7 Rule: Activate automatic backups of EFS file systems if the data is durable and important.
 * 
 * Documentation: "AWS Backup natively integrates with Amazon EFS, and can be used to simplify the creation, migration,
 * restoration, and deletion of backups, while providing improved reporting and auditing."
 */
export class EFS007Rule extends BaseRule {
  constructor() {
    super(
      'EFS-007',
      'HIGH',
      'EFS file system does not have automatic backups configured',
      ['AWS::EFS::FileSystem', 'AWS::Backup::BackupPlan', 'AWS::Backup::BackupSelection']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const resolver = new CloudFormationResolver(allResources);

    // For EFS FileSystem resources
    if (resource.Type === 'AWS::EFS::FileSystem') {
      // Check if the file system has backup policy enabled
      const backupPolicy = resource.Properties?.BackupPolicy;

      // Use resolver to handle intrinsic functions in BackupPolicy.Status
      let hasBackupEnabled = false;
      if (backupPolicy) {
        const resolvedStatus = resolver.resolve(backupPolicy.Status);
        hasBackupEnabled = resolvedStatus.isResolved && resolvedStatus.value === 'ENABLED';
      }

      if (!hasBackupEnabled) {
        // Check if this EFS is included in any AWS Backup selections
        if (allResources && Array.isArray(allResources)) {
          const isIncludedInBackupSelection = this.isIncludedInBackupSelection(resource, allResources, resolver);

          if (!isIncludedInBackupSelection) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Enable the BackupPolicy or include this EFS in an AWS Backup plan.`
            );
          }
        } else {
          // If we don't have allResources, we can only check the BackupPolicy
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Enable the BackupPolicy by setting Status to 'ENABLED'.`
          );
        }
      }
    }

    // For AWS::Backup::BackupSelection resources, check if they include EFS resources
    if (resource.Type === 'AWS::Backup::BackupSelection') {
      // Check for correct schema: Resources should be under Properties.BackupSelection
      const backupSelection = resource.Properties?.BackupSelection;
      if (!backupSelection) {
        return this.createScanResult(
          resource,
          stackName,
          `Backup selection is missing the required BackupSelection property`,
          `Add a BackupSelection property with Resources that include EFS file systems.`
        );
      }

      const selectionResources = backupSelection.Resources;

      if (!selectionResources || !Array.isArray(selectionResources) || selectionResources.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `Backup selection does not specify any resources to back up`,
          `Add EFS ARNs to the BackupSelection.Resources list.`
        );
      }

      // Check if the selection explicitly includes EFS resources
      const includesEfs = selectionResources.some(res => {
        if (typeof res === 'string') {
          return res.includes('elasticfilesystem') || res.includes('efs');
        }

        // Check for intrinsic functions that might include EFS references
        if (typeof res === 'object') {
          // Check for Fn::Sub with EFS references
          if (res['Fn::Sub'] && typeof res['Fn::Sub'] === 'string') {
            return res['Fn::Sub'].includes('elasticfilesystem') || res['Fn::Sub'].includes('efs');
          }

          // Check for Fn::Join that might create an EFS ARN
          if (res['Fn::Join'] && Array.isArray(res['Fn::Join']) &&
            res['Fn::Join'].length === 2 && Array.isArray(res['Fn::Join'][1])) {
            const parts = res['Fn::Join'][1];
            return parts.some(part =>
              typeof part === 'string' &&
              (part.includes('elasticfilesystem') || part.includes('efs'))
            );
          }

          // Check for Ref to EFS resource
          if (res.Ref && typeof res.Ref === 'string') {
            // If it's a reference to a resource, we'll check if it's an EFS resource in isIncludedInBackupSelection
            return true;
          }
        }

        return false;
      });

      // If no explicit EFS resources, check if it has wildcard that would include EFS
      const hasWildcard = selectionResources.some(res => {
        if (typeof res === 'string') {
          return res === '*' || res.endsWith('*');
        }
        return false;
      });

      // If neither explicit EFS resources nor wildcards, suggest including EFS
      if (!includesEfs && !hasWildcard) {
        return this.createScanResult(
          resource,
          stackName,
          `Backup selection does not explicitly include EFS resources`,
          `Add EFS ARNs to the BackupSelection.Resources list or use a wildcard pattern that includes EFS resources.`
        );
      }
    }

    return null;
  }

  private isIncludedInBackupSelection(efsResource: CloudFormationResource, allResources: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
    // Get all backup selections
    const backupSelections = allResources.filter(res => res.Type === 'AWS::Backup::BackupSelection');

    if (backupSelections.length === 0) {
      return false;
    }

    // Check if any backup selection includes this EFS resource
    for (const selection of backupSelections) {
      // Check if this selection is associated with a backup plan via intrinsic function
      const backupPlanId = selection.Properties?.BackupPlanId;
      if (!backupPlanId) {
        continue;
      }

      // Use resolver to check BackupPlanId
      const resolvedBackupPlanId = resolver.resolve(backupPlanId);

      // Skip if we can't resolve the backup plan ID or it doesn't reference any resources
      if (!resolvedBackupPlanId.isResolved && resolvedBackupPlanId.referencedResources.length === 0) {
        continue;
      }

      // Check if any of the referenced resources is a backup plan
      let backupPlanFound = false;
      for (const resourceId of resolvedBackupPlanId.referencedResources) {
        const backupPlan = allResources.find(res =>
          res.Type === 'AWS::Backup::BackupPlan' && res.LogicalId === resourceId
        );

        if (backupPlan) {
          backupPlanFound = true;
          break;
        }
      }

      if (!backupPlanFound) {
        continue; // Skip if backup plan not found
      }

      // Use correct schema: Resources should be under Properties.BackupSelection
      const backupSelection = selection.Properties?.BackupSelection;
      if (!backupSelection) {
        continue;
      }

      const selectionResources = backupSelection.Resources;

      if (!selectionResources || !Array.isArray(selectionResources) || selectionResources.length === 0) {
        continue;
      }

      // Check for EFS ARN patterns or references to this EFS
      const isEfsIncluded = selectionResources.some(res => {
        // Use resolver to handle intrinsic functions
        const resolvedRes = resolver.resolve(res);

        // If we can resolve it to a string, check for EFS patterns
        if (resolvedRes.isResolved) {
          if (typeof resolvedRes.value === 'string') {
            return resolvedRes.value === '*' ||
              resolvedRes.value.includes('elasticfilesystem') ||
              resolvedRes.value.includes('efs');
          }
          return false;
        }

        // If we can't resolve it, check if it references the EFS resource
        if (efsResource && efsResource.LogicalId) {
          return resolvedRes.referencedResources.includes(efsResource.LogicalId);
        }

        // Check for wildcard patterns that would include EFS
        if (typeof res === 'string') {
          return res === '*' ||
            res.includes('elasticfilesystem') ||
            res.includes('efs');
        }

        // For unresolved intrinsic functions, check if they might reference EFS
        if (typeof res === 'object') {
          // Check for Fn::Sub with EFS references
          if (res['Fn::Sub'] && typeof res['Fn::Sub'] === 'string') {
            const subTemplate = res['Fn::Sub'];

            // Check for EFS ARN patterns in the template
            if (subTemplate.includes('elasticfilesystem') || subTemplate.includes('efs')) {
              return true;
            }

            // If we have a specific EFS resource, check for references to it
            if (efsResource && efsResource.LogicalId) {
              // Look for ${LogicalId} pattern in the template
              if (subTemplate.includes(`\${${efsResource.LogicalId}}`)) {
                return true;
              }
            }
          }

          // Check for Ref to EFS resource
          if (res.Ref && efsResource && efsResource.LogicalId && res.Ref === efsResource.LogicalId) {
            return true;
          }

          // Check for Fn::GetAtt with EFS resource
          if (res['Fn::GetAtt'] && Array.isArray(res['Fn::GetAtt']) &&
            efsResource && efsResource.LogicalId && res['Fn::GetAtt'][0] === efsResource.LogicalId) {
            return true;
          }

          // Check for Fn::Join that might create an EFS ARN
          if (res['Fn::Join'] && Array.isArray(res['Fn::Join']) &&
            res['Fn::Join'].length === 2 && Array.isArray(res['Fn::Join'][1])) {
            const parts = res['Fn::Join'][1];

            // Check for EFS patterns in any part
            if (parts.some(part =>
              typeof part === 'string' &&
              (part.includes('elasticfilesystem') || part.includes('efs'))
            )) {
              return true;
            }

            // Check for references to this EFS resource
            if (efsResource && efsResource.LogicalId) {
              if (parts.some(part =>
                (part.Ref && part.Ref === efsResource.LogicalId) ||
                (part['Fn::GetAtt'] && Array.isArray(part['Fn::GetAtt']) && part['Fn::GetAtt'][0] === efsResource.LogicalId)
              )) {
                return true;
              }
            }
          }
        }

        return false;
      });

      if (isEfsIncluded) {
        return true;
      }

      // We can't rely on tags or conditions as they might not be included in the CloudFormation templates
      // So we need to check for explicit EFS resources or wildcards only
    }

    return false;
  }

}

export default new EFS007Rule();
