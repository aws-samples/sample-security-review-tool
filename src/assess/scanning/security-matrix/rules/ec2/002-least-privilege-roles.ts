import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import {
  hasIntrinsicFunction,
  isReferenceToResource,
  extractResourceIdsFromReference
} from '../../../utils/cloudformation-intrinsic-utils.js';
import {
  containsReferenceToResource,
  findRelatedResourcesByType
} from '../../../utils/resource-relationship-utils.js';

/**
 * EC22 Rule: All EC2 instances have an IAM role with minimal privileges
 * 
 * Documentation: "Instances should always have an IAM role that grants at least a few basic rights like 
 * CloudWatch Logs and Systems Manager. If an instance is interactive, it should not grant any access to 
 * AWS resources like S3, EC2, VPC, etc. because the use of that instance's credentials cannot be tied to 
 * an individual person. If an instance is non-interactive, it should be granted the minimum set of privileges 
 * required for it to do its work."
 * 
 * Note: This functionality is partially covered by Checkov rules:
 * - CKV_AWS_60: Ensure IAM role allows only specific services or principals to assume it
 * - CKV_AWS_61: Ensure IAM role policy does not allow wildcard permissions
 * 
 * This rule adds additional checks to ensure EC2 instances have at least CloudWatch Logs and Systems Manager permissions.
 * 
 * Note: This rule has been enhanced to better support CDK-generated CloudFormation templates by handling
 * intrinsic functions like Fn::GetAtt and CDK-style references when resolving instance profiles, roles, and policies.
 */
export class EC2002Rule extends BaseRule {
  constructor() {
    super(
      'EC2-002',
      'HIGH',
      'EC2 instance role violates principle of least privilege',
      ['AWS::IAM::Role', 'AWS::IAM::InstanceProfile', 'AWS::EC2::Instance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // If allResources is not provided, we can't check cross-resource references
    if (!allResources) {
      allResources = [];
    }

    if (resource.Type === 'AWS::EC2::Instance') {
      // Check if the instance has an IAM instance profile
      const instanceProfile = resource.Properties?.IamInstanceProfile;

      if (!instanceProfile) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Attach an IAM role with minimal permissions (at least CloudWatch Logs and Systems Manager access) to the EC2 instance.`
        );
      }

      // If instance profile exists, we'll check its permissions in the IAM role section
      // Handle instanceProfile references, including intrinsic functions
      const profileIds = this.extractResourceIdsFromValue(instanceProfile);

      if (profileIds.length === 0) {
        // If we can't determine the instance profile ID, provide guidance
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Attach an IAM role with minimal permissions (at least CloudWatch Logs and Systems Manager access) to the EC2 instance. Note: This is a guidance-only finding as the instance profile reference could not be fully analyzed.`
        );
      }

      // Find all referenced instance profiles in the template
      const profileResources = profileIds.map(id =>
        allResources.find(r =>
          r.Type === 'AWS::IAM::InstanceProfile' && r.LogicalId === id
        )
      ).filter(Boolean);

      if (profileResources.length === 0) {
        // If we can't find the instance profile in the template, provide guidance
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the instance profile exists and has a role attached with minimal permissions (at least CloudWatch Logs and Systems Manager access). Note: This is a guidance-only finding as the referenced instance profile could not be found in the template.`
        );
      }

      // For each profile resource, check if it has a role attached
      for (const profileResource of profileResources) {
        // Skip undefined resources
        if (!profileResource) continue;

        // Extract the role from the instance profile, handling both Roles array and Role property
        const roleRefs = [];

        // Check Roles array
        if (profileResource.Properties?.Roles && Array.isArray(profileResource.Properties.Roles)) {
          roleRefs.push(...profileResource.Properties.Roles);
        }

        // Check Role property
        if (profileResource.Properties?.Role) {
          roleRefs.push(profileResource.Properties.Role);
        }

        // Handle Fn::GetAtt references to roles
        if (profileResource.Properties?.Roles && typeof profileResource.Properties.Roles === 'object' && !Array.isArray(profileResource.Properties.Roles)) {
          const rolesStr = JSON.stringify(profileResource.Properties.Roles);
          if (rolesStr.includes('Fn::GetAtt') || rolesStr.includes('Ref')) {
            // We found some kind of reference, but can't fully analyze it
            // Continue to the next profile resource
            continue;
          }
        }

        if (roleRefs.length === 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Ensure the instance profile has a role attached with minimal permissions (at least CloudWatch Logs and Systems Manager access).`
          );
        }

        // For each role reference, try to find the corresponding role resource
        const roleIds = roleRefs.flatMap(ref => this.extractResourceIdsFromValue(ref)).filter(Boolean);

        if (roleIds.length === 0) {
          // If we can't determine any role IDs, continue to the next profile resource
          continue;
        }

        // Find all referenced roles in the template
        const roleResources = roleIds.map(id =>
          allResources.find(r =>
            r.Type === 'AWS::IAM::Role' && r.LogicalId === id
          )
        ).filter(Boolean);

        if (roleResources.length > 0) {
          // We found at least one role resource, so we can analyze it
          // The role-specific checks will be done in the IAM::Role section
          return null;
        }
      }

      // If we've checked all profile resources and couldn't find any roles, provide guidance
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure the instance profile has a role attached with minimal permissions (at least CloudWatch Logs and Systems Manager access). Note: This is a guidance-only finding as the role references could not be fully analyzed.`
      );
    }

    if (resource.Type === 'AWS::IAM::Role') {
      // Check if this role is associated with an EC2 instance
      const isEc2Role = this.isEc2Role(resource, allResources);

      if (!isEc2Role) {
        return null;
      }

      // Check if the role has any policies at all
      const policies = resource.Properties?.Policies || [];
      const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];

      // Skip validation if policies is an intrinsic function
      if (policies && typeof policies === 'object' && !Array.isArray(policies)) {
        const isIntrinsicFunction = Object.keys(policies).some(key => key.startsWith('Fn::') || key === 'Ref');
        if (isIntrinsicFunction) {
          return null; // Skip validation for intrinsic functions
        }
      }

      // Skip validation if managedPolicyArns is an intrinsic function
      if (managedPolicyArns && typeof managedPolicyArns === 'object' && !Array.isArray(managedPolicyArns)) {
        const isIntrinsicFunction = Object.keys(managedPolicyArns).some(key => key.startsWith('Fn::') || key === 'Ref');
        if (isIntrinsicFunction) {
          return null; // Skip validation for intrinsic functions
        }
      }

      // Check if the role has any policies at all
      if (policies.length === 0 && managedPolicyArns.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add policies to the IAM role that grant at least CloudWatch Logs and Systems Manager access.`
        );
      }

      // Check for overly permissive policies
      return this.checkRolePermissions(resource, stackName);
    }

    else if (resource.Type === 'AWS::IAM::InstanceProfile') {
      // Extract the role from the instance profile
      const roleRef = resource.Properties?.Roles?.[0] || resource.Properties?.Role;

      if (!roleRef) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Attach a role to the instance profile with minimal permissions (at least CloudWatch Logs and Systems Manager access).`
        );
      }

      // Handle role references, including intrinsic functions
      const roleRefs = [];

      // Check Roles array
      if (resource.Properties?.Roles && Array.isArray(resource.Properties.Roles)) {
        roleRefs.push(...resource.Properties.Roles);
      }

      // Check Role property
      if (resource.Properties?.Role) {
        roleRefs.push(resource.Properties.Role);
      }

      // Handle Fn::GetAtt references to roles
      if (resource.Properties?.Roles && typeof resource.Properties.Roles === 'object' && !Array.isArray(resource.Properties.Roles)) {
        const rolesStr = JSON.stringify(resource.Properties.Roles);
        if (rolesStr.includes('Fn::GetAtt') || rolesStr.includes('Ref')) {
          // We found some kind of reference, but can't fully analyze it
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Ensure the instance profile has a role attached with minimal permissions (at least CloudWatch Logs and Systems Manager access). Note: This is a guidance-only finding as the role references could not be fully analyzed.`
          );
        }
      }

      if (roleRefs.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Attach a role to the instance profile with minimal permissions (at least CloudWatch Logs and Systems Manager access).`
        );
      }

      // For each role reference, try to find the corresponding role resource
      const roleIds = roleRefs.flatMap(ref => this.extractResourceIdsFromValue(ref)).filter(Boolean);

      if (roleIds.length === 0) {
        // If we can't determine any role IDs, provide guidance
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the instance profile has a role attached with minimal permissions (at least CloudWatch Logs and Systems Manager access). Note: This is a guidance-only finding as the role references could not be fully analyzed.`
        );
      }

      // Find all referenced roles in the template
      const roleResources = roleIds.map(id =>
        allResources.find(r =>
          r.Type === 'AWS::IAM::Role' && r.LogicalId === id
        )
      ).filter(Boolean);

      if (roleResources.length === 0) {
        // If we can't find any roles in the template, provide guidance
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Ensure the referenced role exists and has minimal permissions (at least CloudWatch Logs and Systems Manager access). Note: This is a guidance-only finding as the referenced role could not be found in the template.`
        );
      }

      // Check each role resource
      for (const roleResource of roleResources) {
        if (!roleResource) continue; // Skip undefined resources

        // Check if the role has any policies at all
        const policies = this.extractPolicies(roleResource);
        const managedPolicyArns = this.extractManagedPolicyArns(roleResource);

        // If we couldn't extract policies or managed policy ARNs due to intrinsic functions,
        // continue to the next role resource
        if (policies === null && managedPolicyArns === null) {
          continue;
        }

        // Check if the role has any policies at all
        if ((policies && policies.length === 0) && (managedPolicyArns && managedPolicyArns.length === 0)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Add policies to the IAM role that grant at least CloudWatch Logs and Systems Manager access.`
          );
        }
      }
    }

    return null;
  }

  private checkRolePermissions(resource: CloudFormationResource | undefined, stackName: string): ScanResult | null {
    if (!resource) return null;
    // Extract policies and managed policy ARNs, handling intrinsic functions
    const policies = this.extractPolicies(resource);
    const managedPolicyArns = this.extractManagedPolicyArns(resource);

    // If we couldn't extract policies or managed policy ARNs due to intrinsic functions,
    // provide guidance
    if (policies === null && managedPolicyArns === null) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure the IAM role has at least CloudWatch Logs and Systems Manager permissions. Consider adding the AmazonSSMManagedInstanceCore and CloudWatchAgentServerPolicy managed policies. Note: This is a guidance-only finding as the role policies could not be fully analyzed.`
      );
    }

    // Check if the role has basic CloudWatch Logs and SSM permissions
    let hasCloudWatchLogsPermission = false;
    let hasSSMPermission = false;

    // Check inline policies
    if (policies) {
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;

        // Handle intrinsic functions in policy document
        if (policyDocument && typeof policyDocument === 'object' && !Array.isArray(policyDocument)) {
          const isIntrinsicFunction = Object.keys(policyDocument).some(key => key.startsWith('Fn::') || key === 'Ref');
          if (isIntrinsicFunction) {
            // Try to extract information from the stringified object
            const policyStr = JSON.stringify(policyDocument);
            if (policyStr.includes('logs:')) {
              hasCloudWatchLogsPermission = true;
            }
            if (policyStr.includes('ssm:')) {
              hasSSMPermission = true;
            }
            continue; // Skip further validation for this policy
          }
        }

        if (policyDocument) {
          const statements = policyDocument.Statement;

          if (statements && Array.isArray(statements)) {
            for (const statement of statements) {
              // Check for CloudWatch Logs permissions
              if (this.hasCloudWatchLogsPermission(statement)) {
                hasCloudWatchLogsPermission = true;
              }

              // Check for SSM permissions
              if (this.hasSSMPermission(statement)) {
                hasSSMPermission = true;
              }

              // Check for overly permissive statements
              if (this.isOverlyPermissiveStatement(statement)) {
                return this.createScanResult(
                  resource,
                  stackName,
                  `${this.description}`,
                  `Modify the IAM policy to follow the principle of least privilege by replacing wildcard actions with specific actions and restricting resources to only those needed.`
                );
              }
            }
          }
        }
      }
    }

    // Check managed policies
    if (managedPolicyArns) {
      for (const policyArn of managedPolicyArns) {
        // Handle intrinsic functions in policy ARN
        if (policyArn && typeof policyArn === 'object' && !Array.isArray(policyArn)) {
          const isIntrinsicFunction = Object.keys(policyArn).some(key => key.startsWith('Fn::') || key === 'Ref');
          if (isIntrinsicFunction) {
            // Try to extract information from the stringified object
            const arnStr = JSON.stringify(policyArn);
            if (arnStr.includes('CloudWatchLogs') || arnStr.includes('CloudWatchAgent')) {
              hasCloudWatchLogsPermission = true;
            }
            if (arnStr.includes('SSM')) {
              hasSSMPermission = true;
            }
            continue; // Skip further validation for this policy ARN
          }
        }

        // Check for CloudWatch Logs and SSM managed policies
        if (typeof policyArn === 'string') {
          if (policyArn.includes('CloudWatchLogsReadOnlyAccess') ||
            policyArn.includes('CloudWatchAgentServerPolicy')) {
            hasCloudWatchLogsPermission = true;
          }

          if (policyArn.includes('AmazonSSMManagedInstanceCore') ||
            policyArn.includes('AmazonSSMFullAccess') ||
            policyArn.includes('AmazonSSMReadOnlyAccess')) {
            hasSSMPermission = true;
          }

          if (this.isOverlyPermissiveManagedPolicy(policyArn)) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Replace the overly permissive managed policy with a custom policy that grants only the specific permissions required by the EC2 instance.`
            );
          }
        }
      }
    }

    // Check if the role has the minimum required permissions
    if (!hasCloudWatchLogsPermission || !hasSSMPermission) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure the IAM role has at least CloudWatch Logs and Systems Manager permissions. Consider adding the AmazonSSMManagedInstanceCore and CloudWatchAgentServerPolicy managed policies.`
      );
    }

    return null;
  }

  private hasCloudWatchLogsPermission(statement: any): boolean {
    if (statement.Effect !== 'Allow') {
      return false;
    }

    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

    return actions.some((action: any) =>
      typeof action === 'string' &&
      (action.includes('logs:') || action === 'logs:*')
    );
  }

  private hasSSMPermission(statement: any): boolean {
    if (statement.Effect !== 'Allow') {
      return false;
    }

    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

    return actions.some((action: any) =>
      typeof action === 'string' &&
      (action.includes('ssm:') || action === 'ssm:*')
    );
  }

  private isEc2Role(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Method 1: Check the assume role policy document
    if (this.hasEc2ServicePrincipal(resource)) {
      return true;
    }

    // Method 2: Check for EC2-related role name, path, or logical ID
    if (this.hasEc2NameOrPath(resource)) {
      return true;
    }

    // Method 3: Check if this role is referenced by an EC2 instance or instance profile
    if (allResources && this.isReferencedByEc2Resources(resource, allResources)) {
      return true;
    }

    return false;
  }

  /**
   * Check if the role has an EC2 service principal in its assume role policy
   */
  private hasEc2ServicePrincipal(resource: CloudFormationResource): boolean {
    const assumeRolePolicyDocument = resource.Properties?.AssumeRolePolicyDocument;

    if (!assumeRolePolicyDocument) {
      return false;
    }

    // Handle intrinsic functions in AssumeRolePolicyDocument
    if (typeof assumeRolePolicyDocument === 'object' && !Array.isArray(assumeRolePolicyDocument)) {
      // If it's an intrinsic function directly
      if (hasIntrinsicFunction(assumeRolePolicyDocument)) {
        // Check if the stringified version contains ec2.amazonaws.com
        const docString = JSON.stringify(assumeRolePolicyDocument);
        if (docString.includes('ec2.amazonaws.com')) {
          return true;
        }
        return false;
      }

      const statements = assumeRolePolicyDocument.Statement;

      if (statements && Array.isArray(statements)) {
        for (const statement of statements) {
          const principal = statement.Principal;

          if (principal && principal.Service) {
            // Handle array of services
            if (Array.isArray(principal.Service)) {
              if (principal.Service.some((service: any) =>
                typeof service === 'string' && service === 'ec2.amazonaws.com'
              )) {
                return true;
              }
            }
            // Handle string service
            else if (typeof principal.Service === 'string' && principal.Service === 'ec2.amazonaws.com') {
              return true;
            }
            // Handle intrinsic function in Service
            else if (typeof principal.Service === 'object' && principal.Service !== null) {
              const serviceStr = JSON.stringify(principal.Service);
              if (serviceStr.includes('ec2.amazonaws.com')) {
                return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if the role has EC2-related name, path, or logical ID
   */
  private hasEc2NameOrPath(resource: CloudFormationResource): boolean {
    // Check role name
    const roleName = resource.Properties?.RoleName;
    if (typeof roleName === 'string' && roleName.toLowerCase().includes('ec2')) {
      return true;
    } else if (typeof roleName === 'object' && roleName !== null) {
      const nameStr = JSON.stringify(roleName);
      if (nameStr.toLowerCase().includes('ec2')) {
        return true;
      }
    }

    // Check path
    const path = resource.Properties?.Path;
    if (typeof path === 'string' && path.toLowerCase().includes('ec2')) {
      return true;
    } else if (typeof path === 'object' && path !== null) {
      const pathStr = JSON.stringify(path);
      if (pathStr.toLowerCase().includes('ec2')) {
        return true;
      }
    }

    // Check logical ID
    if (resource.LogicalId && resource.LogicalId.toLowerCase().includes('ec2')) {
      return true;
    }

    return false;
  }

  /**
   * Check if the role is referenced by EC2 instances or instance profiles
   */
  private isReferencedByEc2Resources(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    if (!resource.LogicalId) return false;

    // Use the resource relationship utility to find related EC2 resources
    const ec2ResourceTypes = ['AWS::EC2::Instance', 'AWS::IAM::InstanceProfile'];
    const relatedResources = findRelatedResourcesByType(resource, ec2ResourceTypes, allResources);

    // If there are any related EC2 resources, this role is referenced by EC2
    if (relatedResources.length > 0) {
      return true;
    }

    // Additional check for instance profiles that reference this role
    const instanceProfiles = allResources.filter(r => r.Type === 'AWS::IAM::InstanceProfile');
    for (const profile of instanceProfiles) {
      // Check Roles array
      const roles = profile.Properties?.Roles;
      if (Array.isArray(roles)) {
        for (const role of roles) {
          if (isReferenceToResource(role, resource.LogicalId)) {
            return true;
          }
        }
      }

      // Check Role property
      const role = profile.Properties?.Role;
      if (isReferenceToResource(role, resource.LogicalId)) {
        return true;
      }
    }

    // Check for EC2 instances that reference instance profiles that reference this role
    const ec2Instances = allResources.filter(r => r.Type === 'AWS::EC2::Instance');
    for (const instance of ec2Instances) {
      const instanceProfile = instance.Properties?.IamInstanceProfile;

      if (!instanceProfile) continue;

      // If it's a direct reference to an instance profile
      if (typeof instanceProfile === 'string') {
        const profile = instanceProfiles.find(p => p.LogicalId === instanceProfile);
        if (profile && containsReferenceToResource(profile, resource.LogicalId)) {
          return true;
        }
      }
      // If it's an intrinsic function
      else if (typeof instanceProfile === 'object' && instanceProfile !== null) {
        // Extract the profile ID from the reference
        const ids = extractResourceIdsFromReference(instanceProfile);

        for (const profileId of ids) {
          const profile = instanceProfiles.find(p => p.LogicalId === profileId);
          if (profile && containsReferenceToResource(profile, resource.LogicalId)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private isOverlyPermissiveStatement(statement: any): boolean {
    // Check if the statement is overly permissive

    // Only check Allow statements
    if (statement.Effect !== 'Allow') {
      return false;
    }

    // Check for wildcard actions
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

    for (const action of actions) {
      if (action === '*' || action.endsWith('*')) {
        // Check if the resource is also a wildcard
        const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

        for (const resource of resources) {
          if (resource === '*') {
            return true;
          }
        }
      }
    }

    return false;
  }

  private isOverlyPermissiveManagedPolicy(policyArn: string): boolean {
    // Check if the managed policy is overly permissive

    // List of known overly permissive managed policies
    const overlyPermissivePolicies = [
      'arn:aws:iam::aws:policy/AdministratorAccess',
      'arn:aws:iam::aws:policy/PowerUserAccess',
      'arn:aws:iam::aws:policy/AmazonS3FullAccess',
      'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
      'arn:aws:iam::aws:policy/AmazonRDSFullAccess',
      'arn:aws:iam::aws:policy/AmazonEC2FullAccess',
      'arn:aws:iam::aws:policy/AmazonSNSFullAccess',
      'arn:aws:iam::aws:policy/AmazonSQSFullAccess',
      'arn:aws:iam::aws:policy/AmazonKinesisFullAccess',
      'arn:aws:iam::aws:policy/IAMFullAccess'
    ];

    return overlyPermissivePolicies.includes(policyArn);
  }

  /**
   * Extract a resource ID from a reference
   * @param ref The reference to extract from
   * @returns The resource ID or null if it can't be determined
   */
  /**
   * Extract resource IDs from a value, handling various reference formats
   * @param value The value to extract from
   * @returns Array of resource IDs
   */
  private extractResourceIdsFromValue(value: any): string[] {
    // Use the utility function from cloudformation-intrinsic-utils.js
    return extractResourceIdsFromReference(value);
  }

  /**
   * Extract policies from a role resource, handling intrinsic functions
   * @param roleResource The role resource
   * @returns Array of policies, or null if policies can't be determined
   */
  private extractPolicies(roleResource: CloudFormationResource): any[] | null {
    const policies = roleResource.Properties?.Policies;

    // If policies is undefined, return an empty array
    if (policies === undefined) {
      return [];
    }

    // If policies is an array, return it
    if (Array.isArray(policies)) {
      return policies;
    }

    // If policies is an object, check if it's an intrinsic function
    if (typeof policies === 'object' && policies !== null) {
      const isIntrinsicFunction = Object.keys(policies).some(key => key.startsWith('Fn::') || key === 'Ref');
      if (isIntrinsicFunction) {
        // Try to extract information from the stringified object
        const policiesStr = JSON.stringify(policies);
        if (policiesStr.includes('logs:') || policiesStr.includes('ssm:')) {
          // We found some permissions, but can't fully analyze them
          return [];
        }
        return null; // Can't determine policies
      }
    }

    return []; // Default to empty array
  }

  /**
   * Extract managed policy ARNs from a role resource, handling intrinsic functions
   * @param roleResource The role resource
   * @returns Array of managed policy ARNs, or null if ARNs can't be determined
   */
  private extractManagedPolicyArns(roleResource: CloudFormationResource): any[] | null {
    const managedPolicyArns = roleResource.Properties?.ManagedPolicyArns;

    // If managedPolicyArns is undefined, return an empty array
    if (managedPolicyArns === undefined) {
      return [];
    }

    // If managedPolicyArns is an array, return it
    if (Array.isArray(managedPolicyArns)) {
      return managedPolicyArns;
    }

    // If managedPolicyArns is an object, check if it's an intrinsic function
    if (typeof managedPolicyArns === 'object' && managedPolicyArns !== null) {
      const isIntrinsicFunction = Object.keys(managedPolicyArns).some(key => key.startsWith('Fn::') || key === 'Ref');
      if (isIntrinsicFunction) {
        // Try to extract information from the stringified object
        const arnsStr = JSON.stringify(managedPolicyArns);
        if (arnsStr.includes('CloudWatchLogs') || arnsStr.includes('SSM') ||
          arnsStr.includes('AmazonSSMManagedInstanceCore') || arnsStr.includes('CloudWatchAgentServerPolicy')) {
          // We found some managed policies, but can't fully analyze them
          return [];
        }
        return null; // Can't determine managed policy ARNs
      }
    }

    return []; // Default to empty array
  }
}

export default new EC2002Rule();
