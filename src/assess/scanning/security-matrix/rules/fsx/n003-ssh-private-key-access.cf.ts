import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * FSxN3 Rule: If SSH is used to access the file system and/or SVMs, is this access conducted via private key, rather than using a password?
 * 
 * Documentation: "With FSxN, users can SSH to the VMs via a private key, rather than using a password. The default implementation is to use a password."
 */
export class FSxN003Rule extends BaseRule {
  constructor() {
    super(
      'FSxN-003',
      'HIGH',
      'SSH access to file system and/or SVMs is not configured to use private key authentication',
      [
        'AWS::FSx::FileSystem',
        'AWS::FSx::StorageVirtualMachine'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const resolver = new CloudFormationResolver(allResources || [resource]);

    // For FSx FileSystem resources
    if (resource.Type === 'AWS::FSx::FileSystem') {
      const fileSystemType = resource.Properties?.FileSystemType;

      // This rule is primarily for ONTAP (FSxN) file systems
      const resolvedFileSystemType = resolver.resolve(fileSystemType);
      if (!resolvedFileSystemType.isResolved || resolvedFileSystemType.value !== 'ONTAP') {
        return null;
      }

      const ontapConfiguration = resource.Properties?.OntapConfiguration;

      if (!ontapConfiguration) {
        return null;
      }

      // Check if SSH key is configured for the file system
      const fsxAdminPassword = ontapConfiguration.FsxAdminPassword;

      if (fsxAdminPassword) {
        // Resolve the password
        const resolvedPassword = resolver.resolve(fsxAdminPassword);

        // If we can't resolve the password due to intrinsic functions, we need to fail the check
        if (!resolvedPassword.isResolved) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Unable to verify authentication method at scan time due to intrinsic functions. Ensure SSH key-based authentication is configured for the ONTAP file system instead of using a password.`
          );
        }

        // If a password is explicitly set, recommend using SSH key instead
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure SSH key-based authentication for the ONTAP file system instead of using a password.`
        );
      }
    }

    // For FSx StorageVirtualMachine resources
    if (resource.Type === 'AWS::FSx::StorageVirtualMachine') {
      // Check if the SVM has a password configured
      const svmAdminPassword = resource.Properties?.SvmAdminPassword;

      if (svmAdminPassword) {
        // Resolve the password
        const resolvedPassword = resolver.resolve(svmAdminPassword);

        // If we can't resolve the password due to intrinsic functions, we need to fail the check
        if (!resolvedPassword.isResolved) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Unable to verify authentication method at scan time due to intrinsic functions. Ensure SSH key-based authentication is configured for the Storage Virtual Machine instead of using a password.`
          );
        }

        // If a password is explicitly set, recommend using SSH key instead
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure SSH key-based authentication for the Storage Virtual Machine instead of using a password.`
        );
      }

      // Check if the SVM has Active Directory configured
      const activeDirectoryConfiguration = resource.Properties?.ActiveDirectoryConfiguration;

      if (activeDirectoryConfiguration) {
        // Active Directory authentication is acceptable, but recommend configuring SSH keys as well
        const adPassword = activeDirectoryConfiguration.Password;
        const selfManagedAD = activeDirectoryConfiguration.SelfManagedActiveDirectoryConfiguration;

        // Resolve AD passwords
        const resolvedAdPassword = resolver.resolve(adPassword);
        const resolvedSelfManagedAdPassword = selfManagedAD ? resolver.resolve(selfManagedAD.Password) : { isResolved: true, value: null };

        // Check for unresolvable intrinsic functions in AD passwords
        if (!resolvedAdPassword.isResolved || (selfManagedAD && !resolvedSelfManagedAdPassword.isResolved)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Unable to verify authentication method at scan time due to intrinsic functions. In addition to Active Directory authentication, configure SSH key-based authentication for the Storage Virtual Machine.`
          );
        }

        if (adPassword || (selfManagedAD && selfManagedAD.Password)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `In addition to Active Directory authentication, configure SSH key-based authentication for the Storage Virtual Machine.`
          );
        }
      } else {
        // If no authentication method is specified, recommend SSH key authentication
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure SSH key-based authentication for the Storage Virtual Machine.`
        );
      }
    }

    return null;
  }
}

export default new FSxN003Rule();
