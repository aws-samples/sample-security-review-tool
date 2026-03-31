import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { containsPattern } from '../../../utils/cloudformation-intrinsic-utils.js';
import { hasRelationshipWithResourceTypes } from '../../../utils/resource-relationship-utils.js';

/**
 * IoTSiteWise-032 Rule: Ensure that separate permissions/roles are assigned for service users, service administrators, IoT SiteWise Monitor administrators, and IAM administrators.
 * 
 * Documentation: "AWS IoT SiteWise IoTSiteWise-032: Ensure that separate permissions/roles are assigned for service users, service administrators, IoT SiteWise Monitor administrators, and IAM adminstrators.
 * Discuss and implement a user access control strategy to separate duties and differentiate IoT users, SiteWise admins and users, and other stakeholders. 
 * See https://docs.aws.amazon.com/iot-sitewise/latest/userguide/security-iam.html"
 * 
 * IMPORTANT: This rule is specifically targeted at IoT SiteWise resources only, not general IoT Core resources.
 * It evaluates role and permission assignments for IoT SiteWise administrators and users.
 */
export class IoT032Rule extends BaseRule {
  constructor() {
    super(
      'IOTSITEWISE-032',
      'HIGH',
      'IoT SiteWise permissions/roles not properly separated',
      [
        'AWS::IoTSiteWise::AccessPolicy',
        'AWS::IoTSiteWise::Portal'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (missing Properties)`,
        `Configure proper permissions and separation of duties for IoT SiteWise resources.`
      );
    }

    // Evaluate IoT SiteWise Access Policies
    if (resource.Type === 'AWS::IoTSiteWise::AccessPolicy') {
      return this.evaluateAccessPolicy(resource, stackName);
    }

    // Evaluate IoT SiteWise Portals
    if (resource.Type === 'AWS::IoTSiteWise::Portal') {
      return this.evaluatePortal(resource, stackName, allResources);
    }



    return null;
  }

  /**
   * Evaluate IoT SiteWise Access Policy for proper role separation
   */
  private evaluateAccessPolicy(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const accessPermission = resource.Properties?.AccessPolicyPermission;
    const accessPolicyIdentity = resource.Properties?.AccessPolicyIdentity;

    // Check if access policy has defined permission and identity
    if (!accessPermission || !accessPolicyIdentity) {
      const issueMessage = `${this.description} (Access policy missing permission or identity)`;
      const fix = 'Define both permission and identity in access policies';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if both user and admin permissions are granted to same identity
    // (Indicates poor separation of duties)
    if (this.hasOverlappingPermissions(accessPermission, accessPolicyIdentity)) {
      const issueMessage = `${this.description} (Access policy grants both user and admin permissions to same identity)`;
      const fix = 'Separate user and administrator permissions into different identities';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    return null;
  }

  /**
   * Evaluate IoT SiteWise Portal for proper administrator assignment
   */
  private evaluatePortal(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    const portalAdminUsers = resource.Properties?.PortalAdminUsers;
    const portalContactEmail = resource.Properties?.PortalContactEmail;

    // Check if portal has defined admin users
    if (!portalAdminUsers || !Array.isArray(portalAdminUsers) || portalAdminUsers.length === 0) {
      const issueMessage = `${this.description} (Portal missing admin users)`;
      const fix = 'Define dedicated administrator users for the IoT SiteWise portal';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if portal has a contact email
    if (!portalContactEmail) {
      const issueMessage = `${this.description} (Portal missing contact email)`;
      const fix = 'Provide a contact email for the portal administrator';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if the portal has associated access policies for user vs admin access
    if (allResources) {
      const hasProperAccessPolicies = this.hasPortalAccessPolicies(resource, allResources);
      if (!hasProperAccessPolicies) {
        const issueMessage = `${this.description} (Portal missing separate access policies for users and administrators)`;
        const fix = 'Define separate access policies for users and administrators';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    return null;
  }

  /**
   * Evaluate IAM Role for proper IoT SiteWise permission separation
   */
  private evaluateIAMRole(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if not an IoT SiteWise related role
    if (!this.isIoTSiteWiseRole(resource, allResources)) {
      return null;
    }

    // Detect if the role has overly permissive policies 
    // (i.e., both admin and user level permissions)
    if (this.hasOverlappingRolePermissions(resource)) {
      const issueMessage = `${this.description} (IAM role has overlapping user and administrator permissions)`;
      const fix = 'Separate IoT SiteWise administrative and user permissions into different roles.';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Detect if a single role has both IoT SiteWise and IAM admin permissions
    if (this.hasIAMAndSiteWisePermissions(resource)) {
      const issueMessage = `${this.description} (IAM role has both IoT SiteWise and IAM administrative permissions)`;
      const fix = 'Separate IoT SiteWise management and IAM administration into different roles.';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // If there are multiple roles, check that they're properly separated
    if (allResources) {
      // Get all IoT SiteWise related roles across resources
      const iotSiteWiseRoles = allResources.filter(res =>
        res.Type === 'AWS::IAM::Role' && this.isIoTSiteWiseRole(res, allResources)
      );

      // Check for role assumption chains that might bypass separation of duties
      if (this.hasRoleAssumptionChain(resource, allResources)) {
        const issueMessage = `${this.description} (IAM role can be assumed by other roles, potentially bypassing separation of duties)`;
        const fix = 'Review role trust policies to ensure proper separation of duties.';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }

      if (iotSiteWiseRoles.length > 0 && !this.hasProperRoleSeparation(iotSiteWiseRoles)) {
        const issueMessage = `${this.description} (IoT SiteWise roles do not have proper duty separation)`;
        const fix = 'Create separate roles for service users, service administrators, IoT SiteWise Monitor administrators, and IAM administrators.';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    return null;
  }

  /**
   * Check if a role can be assumed by other roles (role assumption chain)
   */
  private hasRoleAssumptionChain(role: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    // Check if this role's trust policy allows other roles to assume it
    const assumeRolePolicyDoc = role.Properties?.AssumeRolePolicyDocument;
    if (!assumeRolePolicyDoc) {
      return false;
    }

    const statements = assumeRolePolicyDoc.Statement || [];
    if (!Array.isArray(statements)) {
      return false;
    }

    // Check if any statement allows sts:AssumeRole from another IAM role
    for (const statement of statements) {
      if (statement.Effect !== 'Allow') {
        continue;
      }

      // Skip if not allowing sts:AssumeRole
      if (statement.Action !== 'sts:AssumeRole' &&
        !(Array.isArray(statement.Action) && statement.Action.includes('sts:AssumeRole'))) {
        continue;
      }

      // Check if principal is an IAM role
      const principal = statement.Principal;
      if (!principal || !principal.AWS) {
        continue;
      }

      // Find roles that can assume this role
      const roles = Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS];

      // Check if any of these roles have IoT SiteWise permissions
      for (const assumingRoleArn of roles) {
        // Find the role in the resources
        const assumingRole = allResources.find(res =>
          res.Type === 'AWS::IAM::Role' &&
          (res.LogicalId === assumingRoleArn || containsPattern(assumingRoleArn, res.LogicalId))
        );

        if (assumingRole) {
          // Check if the assuming role has a different permission set
          const thisRoleType = this.determineRoleType(role);
          const assumingRoleType = this.determineRoleType(assumingRole);

          // If a role with one type can assume a role with another type,
          // this could bypass separation of duties
          if (thisRoleType !== assumingRoleType &&
            thisRoleType !== 'unknown' &&
            assumingRoleType !== 'unknown') {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Determine the type of a role (service user, service admin, monitor admin, IAM admin)
   */
  private determineRoleType(role: CloudFormationResource): 'serviceUser' | 'serviceAdmin' | 'monitorAdmin' | 'iamAdmin' | 'unknown' {
    const roleJson = JSON.stringify(role.Properties || {});
    const roleName = role.Properties?.RoleName || '';

    // Check for service user role - detect by ReadOnly permissions or User in name
    if ((typeof roleName === 'string' && roleName.toLowerCase().includes('user')) ||
      roleJson.includes('ReadOnly') ||
      roleJson.includes('ReadOnlyAccess') ||
      roleJson.includes('iotsitewise:Get') ||
      roleJson.includes('iotsitewise:List') ||
      roleJson.includes('iotsitewise:Describe')) {
      return 'serviceUser';
    }

    // Check for service admin role - detect by admin permissions
    if ((typeof roleName === 'string' &&
      (roleName.toLowerCase().includes('admin') &&
        !roleName.toLowerCase().includes('monitor') &&
        !roleName.toLowerCase().includes('iam'))) ||
      roleJson.includes('iotsitewise:Create') ||
      roleJson.includes('iotsitewise:Update') ||
      roleJson.includes('iotsitewise:Delete')) {
      return 'serviceAdmin';
    }

    // Check for monitor admin role - specifically for Portal administration
    if ((typeof roleName === 'string' &&
      (roleName.toLowerCase().includes('monitor') ||
        roleName.toLowerCase().includes('portal'))) ||
      (roleJson.includes('Portal') &&
        (roleJson.includes('Admin') || roleJson.includes('ADMINISTRATOR') ||
          roleJson.includes('iotsitewise:CreatePortal') ||
          roleJson.includes('iotsitewise:UpdatePortal')))) {
      return 'monitorAdmin';
    }

    // Check for IAM admin role - specifically for IAM permissions
    if ((typeof roleName === 'string' &&
      (roleName.toLowerCase().includes('iam'))) ||
      roleJson.includes('iam:Create') ||
      roleJson.includes('iam:Delete') ||
      roleJson.includes('iam:Put')) {
      return 'iamAdmin';
    }

    return 'unknown';
  }

  /**
   * Evaluate IAM Policy for proper IoT SiteWise permission separation
   */
  private evaluateIAMPolicy(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if not an IoT SiteWise related policy
    if (!this.isIoTSiteWisePolicy(resource, allResources)) {
      return null;
    }

    // Check if the policy has mixed permissions (both user and admin)
    if (this.hasMixedPolicyPermissions(resource, allResources)) {
      const issueMessage = `${this.description} (IAM policy mixes user and administrator permissions)`;
      const fix = 'Separate IoT SiteWise user and administrator permissions into different policies.';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if this policy is attached to multiple entities with different roles
    if (allResources) {
      const attachedEntities = this.findPolicyAttachments(resource, allResources);

      if (attachedEntities.length > 1) {
        // Check if the attached entities have different roles (e.g., user and admin)
        const entityTypes = new Set(attachedEntities.map(entity => {
          if (entity.Type === 'AWS::IAM::Role') {
            return this.determineRoleType(entity);
          }
          return 'unknown';
        }));

        // If policy is attached to entities with different roles (excluding 'unknown'),
        // this could violate separation of duties
        const knownTypes = Array.from(entityTypes).filter(type => type !== 'unknown');
        if (knownTypes.length > 1) {
          const issueMessage = `${this.description} (IAM policy is attached to multiple entities with different roles)`;
          const fix = 'Create separate policies for each role type.';
          return this.createScanResult(resource, stackName, issueMessage, fix);
        }
      }
    }

    return null;
  }

  /**
   * Find entities that a policy is attached to
   */
  private findPolicyAttachments(policy: CloudFormationResource, allResources: CloudFormationResource[]): CloudFormationResource[] {
    const attachedEntities: CloudFormationResource[] = [];

    // Check for managed policy attachments
    for (const resource of allResources) {
      if (['AWS::IAM::Role', 'AWS::IAM::User', 'AWS::IAM::Group'].includes(resource.Type)) {
        const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];

        if (Array.isArray(managedPolicyArns)) {
          for (const arn of managedPolicyArns) {
            if (containsPattern(arn, policy.LogicalId)) {
              attachedEntities.push(resource);
              break;
            }
          }
        }
      }
    }

    // For inline policies, check if the policy name is referenced
    if (policy.Type === 'AWS::IAM::Policy') {
      const policyName = policy.Properties?.PolicyName;

      if (policyName) {
        // Check roles, users, and groups that this policy is attached to
        const policyGroups = policy.Properties?.Groups || [];
        const policyRoles = policy.Properties?.Roles || [];
        const policyUsers = policy.Properties?.Users || [];

        // If arrays are not defined, initialize them as empty arrays to prevent errors
        const groups = Array.isArray(policyGroups) ? policyGroups : [];
        const roles = Array.isArray(policyRoles) ? policyRoles : [];
        const users = Array.isArray(policyUsers) ? policyUsers : [];

        // Add resources that are referenced in these arrays
        for (const resource of allResources) {
          if (resource.Type === 'AWS::IAM::Role' &&
            roles.some((role: string) => containsPattern(role, resource.LogicalId))) {
            attachedEntities.push(resource);
          } else if (resource.Type === 'AWS::IAM::Group' &&
            groups.some((group: string) => containsPattern(group, resource.LogicalId))) {
            attachedEntities.push(resource);
          } else if (resource.Type === 'AWS::IAM::User' &&
            users.some((user: string) => containsPattern(user, resource.LogicalId))) {
            attachedEntities.push(resource);
          }
        }
      }
    }

    return attachedEntities;
  }

  /**
   * Evaluate IAM Group for proper IoT SiteWise permission separation
   */
  private evaluateIAMGroup(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if not an IoT SiteWise related group
    if (!this.isIoTSiteWiseGroup(resource, allResources)) {
      return null;
    }

    // Check if group has mixed permissions
    if (this.hasGroupMixedPermissions(resource)) {
      const issueMessage = `${this.description} (IAM group mixes user and administrator permissions)`;
      const fix = 'Separate IoT SiteWise user and administrator permissions into different groups.';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // Check if this group has users that are also members of other groups with different permissions
    if (allResources) {
      // Find IoT SiteWise related groups
      const iotGroups = allResources.filter(res =>
        res.Type === 'AWS::IAM::Group' &&
        this.isIoTSiteWiseGroup(res, allResources) &&
        res.LogicalId !== resource.LogicalId
      );

      // Check if any users in this group are also in other IoT SiteWise groups
      const usersInThisGroup = this.findUsersInGroup(resource, allResources);

      for (const otherGroup of iotGroups) {
        const usersInOtherGroup = this.findUsersInGroup(otherGroup, allResources);

        // Find overlapping users
        const overlappingUsers = usersInThisGroup.filter(user =>
          usersInOtherGroup.some(otherUser => otherUser.LogicalId === user.LogicalId)
        );

        if (overlappingUsers.length > 0) {
          // Check if the groups have different permission sets
          const thisGroupPermissionType = this.determineGroupPermissionType(resource, allResources);
          const otherGroupPermissionType = this.determineGroupPermissionType(otherGroup, allResources);

          if (thisGroupPermissionType !== otherGroupPermissionType &&
            thisGroupPermissionType !== 'unknown' &&
            otherGroupPermissionType !== 'unknown') {
            const issueMessage = `${this.description} (Users belong to multiple groups with different permission levels)`;
            const fix = 'Ensure users are only members of groups that align with their role.';
            return this.createScanResult(resource, stackName, issueMessage, fix);
          }
        }
      }
    }

    return null;
  }

  /**
   * Find users that are members of a group
   */
  private findUsersInGroup(group: CloudFormationResource, allResources: CloudFormationResource[]): CloudFormationResource[] {
    const users: CloudFormationResource[] = [];

    // Find AWS::IAM::UserToGroupAddition resources that reference this group
    const userToGroupAdditions = allResources.filter(res =>
      res.Type === 'AWS::IAM::UserToGroupAddition' &&
      containsPattern(res.Properties?.GroupName, group.LogicalId)
    );

    // Find users referenced in these resources
    for (const addition of userToGroupAdditions) {
      const userNames = addition.Properties?.Users || [];

      if (Array.isArray(userNames)) {
        for (const userName of userNames) {
          // Find the user resource
          const user = allResources.find(res =>
            res.Type === 'AWS::IAM::User' &&
            (res.LogicalId === userName || containsPattern(userName, res.LogicalId))
          );

          if (user) {
            users.push(user);
          }
        }
      }
    }

    // Also check for direct users in the group's Properties.Users
    const groupUsers = group.Properties?.Users || [];
    if (Array.isArray(groupUsers)) {
      for (const userName of groupUsers) {
        const user = allResources.find(res =>
          res.Type === 'AWS::IAM::User' &&
          (res.LogicalId === userName || containsPattern(userName, res.LogicalId))
        );

        if (user) {
          users.push(user);
        }
      }
    }

    return users;
  }

  /**
   * Determine the permission type of a group (read-only, admin, etc.)
   */
  private determineGroupPermissionType(group: CloudFormationResource, allResources: CloudFormationResource[]): 'admin' | 'user' | 'unknown' {
    const groupJson = JSON.stringify(group.Properties || {});
    const groupName = group.Properties?.GroupName || '';

    // Check for admin indicators in group name
    if (typeof groupName === 'string' &&
      (groupName.toLowerCase().includes('admin') ||
        groupName.toLowerCase().includes('administrator'))) {
      return 'admin';
    }

    // Check for user indicators in group name
    if (typeof groupName === 'string' &&
      (groupName.toLowerCase().includes('user') ||
        groupName.toLowerCase().includes('viewer') ||
        groupName.toLowerCase().includes('readonly'))) {
      return 'user';
    }

    // Check managed policies for admin access
    const managedPolicyArns = group.Properties?.ManagedPolicyArns || [];
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (typeof arn === 'string') {
          if (arn.includes('FullAccess') || arn.includes('Administrator')) {
            return 'admin';
          }

          if (arn.includes('ReadOnly') || arn.includes('Viewer')) {
            return 'user';
          }
        }
      }
    }

    // Check attached policies
    const attachedPolicies = allResources.filter(res =>
      res.Type === 'AWS::IAM::Policy' &&
      this.isPolicyAttachedToGroup(res, group)
    );

    for (const policy of attachedPolicies) {
      const policyDocument = policy.Properties?.PolicyDocument;
      if (policyDocument) {
        const statements = policyDocument.Statement || [];

        if (Array.isArray(statements)) {
          let hasWriteActions = false;
          let hasReadActions = false;

          for (const statement of statements) {
            const action = statement.Action;

            // Check actions for write permissions
            if (Array.isArray(action)) {
              for (const act of action) {
                if (typeof act === 'string') {
                  if (act.includes('Create') ||
                    act.includes('Update') ||
                    act.includes('Delete') ||
                    act.includes('Put')) {
                    hasWriteActions = true;
                  }

                  if (act.includes('Get') ||
                    act.includes('List') ||
                    act.includes('Describe')) {
                    hasReadActions = true;
                  }
                }
              }
            } else if (typeof action === 'string') {
              if (action.includes('Create') ||
                action.includes('Update') ||
                action.includes('Delete') ||
                action.includes('Put')) {
                hasWriteActions = true;
              }

              if (action.includes('Get') ||
                action.includes('List') ||
                action.includes('Describe')) {
                hasReadActions = true;
              }
            }
          }

          if (hasWriteActions) {
            return 'admin';
          }

          if (hasReadActions) {
            return 'user';
          }
        }
      }
    }

    return 'unknown';
  }

  /**
   * Check if an access policy grants overlapping permissions to the same identity
   */
  private hasOverlappingPermissions(permission: any, identity: any): boolean {
    // Check if we have a user identity with administrative permissions
    // or an admin identity with regular user permissions
    const isUserIdentity = identity.User !== undefined;
    const isAdminPermission = permission === 'ADMINISTRATOR';

    const isIAMUserWithAdminPerms = isUserIdentity && isAdminPermission;

    // Allow admin identity to have admin permissions
    // Handle different possible structures of IamUser property
    let isAdminIdentity = false;

    if (identity.IamUser) {
      const iamUser = identity.IamUser;
      // Check if IamUser is a string
      if (typeof iamUser === 'string') {
        isAdminIdentity = iamUser.toLowerCase().includes('admin');
      }
      // Check if IamUser has an id property that's a string
      else if (iamUser.id && typeof iamUser.id === 'string') {
        isAdminIdentity = iamUser.id.toLowerCase().includes('admin');
      }
      // Check if IamUser is an object with another structure
      else if (typeof iamUser === 'object') {
        // Convert to string to check for "admin" anywhere
        const iamUserStr = JSON.stringify(iamUser).toLowerCase();
        isAdminIdentity = iamUserStr.includes('admin');
      }
    }

    const isProperAdminAssignment = isAdminIdentity && isAdminPermission;

    return isIAMUserWithAdminPerms && !isProperAdminAssignment;
  }

  /**
   * Check if a Portal has properly separated access policies
   */
  private hasPortalAccessPolicies(portal: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    const portalId = portal.LogicalId;

    // Find all access policies for this portal
    const accessPolicies = allResources.filter(res =>
      res.Type === 'AWS::IoTSiteWise::AccessPolicy' &&
      JSON.stringify(res.Properties?.AccessPolicyResource || {}).includes(portalId)
    );

    if (accessPolicies.length === 0) {
      // No access policies found for this portal
      return false;
    }

    // Check if there are separate policies for admin and user access
    const adminPolicies = accessPolicies.filter(policy =>
      policy.Properties?.AccessPolicyPermission === 'ADMINISTRATOR'
    );

    const userPolicies = accessPolicies.filter(policy =>
      policy.Properties?.AccessPolicyPermission !== 'ADMINISTRATOR'
    );

    // Check if we have at least one admin policy and at least one user policy
    return adminPolicies.length > 0 && userPolicies.length > 0;
  }

  /**
   * Check if an IAM role is related to IoT SiteWise
   */
  private isIoTSiteWiseRole(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Simple string-based detection (original implementation)
    const roleJson = JSON.stringify(resource.Properties || {});
    const simpleMatch = roleJson.includes('iotsitewise') ||
      roleJson.includes('IoTSiteWise') ||
      roleJson.includes('SiteWise');

    if (simpleMatch) {
      return true;
    }

    // Enhanced detection: Check service principal in assume role policy
    const assumeRolePolicyDoc = resource.Properties?.AssumeRolePolicyDocument;
    if (assumeRolePolicyDoc) {
      try {
        // Check for iotsitewise service principal
        if (this.hasTrustRelationshipWithService(assumeRolePolicyDoc, 'iotsitewise.amazonaws.com')) {
          return true;
        }
      } catch (error) {
        // If parsing fails, fall back to string matching
        const policyStr = JSON.stringify(assumeRolePolicyDoc);
        if (policyStr.includes('iotsitewise.amazonaws.com')) {
          return true;
        }
      }
    }

    // Check policies for IoT SiteWise actions
    const policies = resource.Properties?.Policies || [];
    if (Array.isArray(policies)) {
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;
        if (policyDocument && this.hasIoTSiteWiseActions(policyDocument)) {
          return true;
        }
      }
    }

    // Check for relationships with IoT SiteWise resources
    if (allResources) {
      const iotSiteWiseResourceTypes = [
        'AWS::IoTSiteWise::AccessPolicy',
        'AWS::IoTSiteWise::Portal',
        'AWS::IoTSiteWise::Project',
        'AWS::IoTSiteWise::Dashboard',
        'AWS::IoTSiteWise::Asset',
        'AWS::IoTSiteWise::AssetModel',
        'AWS::IoTSiteWise::Gateway'
      ];

      if (hasRelationshipWithResourceTypes(resource, iotSiteWiseResourceTypes, allResources)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a trust policy document includes a specific service principal
   */
  private hasTrustRelationshipWithService(policyDocument: any, serviceName: string): boolean {
    const statements = policyDocument.Statement || [];

    if (!Array.isArray(statements)) {
      return false;
    }

    for (const statement of statements) {
      if (statement.Effect !== 'Allow') {
        continue;
      }

      // Check Principal.Service
      const principal = statement.Principal;
      if (!principal) {
        continue;
      }

      // Handle Service as string
      if (principal.Service === serviceName) {
        return true;
      }

      // Handle Service as array
      if (Array.isArray(principal.Service) &&
        principal.Service.includes(serviceName)) {
        return true;
      }

      // Handle intrinsic functions with pattern matching
      if (containsPattern(principal.Service, serviceName)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if an IAM role has overlapping user and admin permissions
   */
  private hasOverlappingRolePermissions(resource: CloudFormationResource): boolean {
    const policies = resource.Properties?.Policies || [];
    const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];

    let hasAdminPermissions = false;
    let hasUserPermissions = false;

    // Check inline policies
    if (Array.isArray(policies)) {
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;
        if (policyDocument) {
          const policyJson = JSON.stringify(policyDocument);

          if (policyJson.includes('iotsitewise:Admin') ||
            policyJson.includes('iotsitewise:CreatePortal') ||
            policyJson.includes('iotsitewise:Update') ||
            policyJson.includes('iotsitewise:Delete')) {
            hasAdminPermissions = true;
          }

          if (policyJson.includes('iotsitewise:Describe') ||
            policyJson.includes('iotsitewise:List') ||
            policyJson.includes('iotsitewise:BatchGet') ||
            policyJson.includes('iotsitewise:Get')) {
            hasUserPermissions = true;
          }
        }
      }
    }

    // Check managed policies
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (typeof arn === 'string') {
          if (arn.includes('AWSIoTSiteWiseFullAccess') ||
            arn.includes('AdministratorAccess')) {
            hasAdminPermissions = true;
          }

          if (arn.includes('AWSIoTSiteWiseReadOnlyAccess') ||
            arn.includes('ReadOnlyAccess')) {
            hasUserPermissions = true;
          }
        }
      }
    }

    // Return true if the role has both admin and user permissions
    return hasAdminPermissions && hasUserPermissions;
  }

  /**
   * Check if an IAM role has both IoT SiteWise and IAM admin permissions
   */
  private hasIAMAndSiteWisePermissions(resource: CloudFormationResource): boolean {
    const policies = resource.Properties?.Policies || [];
    const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];

    let hasIAMPermissions = false;
    let hasSiteWisePermissions = false;

    // Check inline policies
    if (Array.isArray(policies)) {
      for (const policy of policies) {
        const policyDocument = policy.PolicyDocument;
        if (policyDocument) {
          const policyJson = JSON.stringify(policyDocument);

          if (policyJson.includes('iam:Create') ||
            policyJson.includes('iam:Delete') ||
            policyJson.includes('iam:Update') ||
            policyJson.includes('iam:Put')) {
            hasIAMPermissions = true;
          }

          if (policyJson.includes('iotsitewise:')) {
            hasSiteWisePermissions = true;
          }
        }
      }
    }

    // Check managed policies
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (typeof arn === 'string') {
          if (arn.includes('IAMFullAccess') ||
            arn.includes('AdministratorAccess')) {
            hasIAMPermissions = true;
          }

          if (arn.includes('IoTSiteWise') ||
            arn.includes('SiteWise')) {
            hasSiteWisePermissions = true;
          }
        }
      }
    }

    // Return true if the role has both IAM admin and SiteWise permissions
    return hasIAMPermissions && hasSiteWisePermissions;
  }

  /**
   * Check if the collection of roles has proper separation of duties
   */
  private hasProperRoleSeparation(roles: CloudFormationResource[]): boolean {
    // For testing purposes with a small number of roles, we'll use a simplified check
    // In a real-world scenario with numerous roles, we would perform a more detailed analysis
    if (roles.length < 4) {
      return false; // Need at least 4 distinct roles for proper separation
    }

    // Define role types to check for
    const roleTypes = {
      serviceUser: false,
      serviceAdmin: false,
      monitorAdmin: false,
      iamAdmin: false
    };

    for (const role of roles) {
      const roleJson = JSON.stringify(role.Properties || {});
      const roleName = role.Properties?.RoleName || '';

      // Check for service user role - detect by ReadOnly permissions or User in name
      if ((typeof roleName === 'string' && roleName.toLowerCase().includes('user')) ||
        roleJson.includes('ReadOnly') ||
        roleJson.includes('ReadOnlyAccess') ||
        roleJson.includes('iotsitewise:Get') ||
        roleJson.includes('iotsitewise:List') ||
        roleJson.includes('iotsitewise:Describe')) {
        roleTypes.serviceUser = true;
        continue; // Skip other checks for this role to ensure separation
      }

      // Check for service admin role - detect by admin permissions
      if ((typeof roleName === 'string' &&
        (roleName.toLowerCase().includes('admin') &&
          !roleName.toLowerCase().includes('monitor') &&
          !roleName.toLowerCase().includes('iam'))) ||
        roleJson.includes('iotsitewise:Create') ||
        roleJson.includes('iotsitewise:Update') ||
        roleJson.includes('iotsitewise:Delete')) {
        roleTypes.serviceAdmin = true;
        continue; // Skip other checks for this role to ensure separation
      }

      // Check for monitor admin role - specifically for Portal administration
      if ((typeof roleName === 'string' &&
        (roleName.toLowerCase().includes('monitor') ||
          roleName.toLowerCase().includes('portal'))) ||
        (roleJson.includes('Portal') &&
          (roleJson.includes('Admin') || roleJson.includes('ADMINISTRATOR') ||
            roleJson.includes('iotsitewise:CreatePortal') ||
            roleJson.includes('iotsitewise:UpdatePortal')))) {
        roleTypes.monitorAdmin = true;
        continue; // Skip other checks for this role to ensure separation
      }

      // Check for IAM admin role - specifically for IAM permissions
      if ((typeof roleName === 'string' &&
        (roleName.toLowerCase().includes('iam'))) ||
        roleJson.includes('iam:Create') ||
        roleJson.includes('iam:Delete') ||
        roleJson.includes('iam:Put')) {
        roleTypes.iamAdmin = true;
        continue; // Skip other checks for this role to ensure separation
      }
    }

    // For debugging purposes, we'll log the detected role types
    // console.log('Detected role types:', roleTypes);

    // Check if we have all four role types
    return roleTypes.serviceUser &&
      roleTypes.serviceAdmin &&
      roleTypes.monitorAdmin &&
      roleTypes.iamAdmin;
  }

  /**
   * Check if an IAM policy is related to IoT SiteWise
   */
  private isIoTSiteWisePolicy(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Simple string-based detection (original implementation)
    const policyJson = JSON.stringify(resource.Properties || {});
    const simpleMatch = policyJson.includes('iotsitewise') ||
      policyJson.includes('IoTSiteWise') ||
      policyJson.includes('SiteWise');

    if (simpleMatch) {
      return true;
    }

    // Enhanced detection: Check policy actions
    const policyDocument = resource.Properties?.PolicyDocument;
    if (policyDocument) {
      if (this.hasIoTSiteWiseActions(policyDocument)) {
        return true;
      }
    }

    // Check for relationships with IoT SiteWise resources
    if (allResources) {
      // Check if this policy is attached to a role that is related to IoT SiteWise
      const attachedRoles = allResources.filter(res =>
        res.Type === 'AWS::IAM::Role' &&
        this.isIoTSiteWiseRole(res, allResources) &&
        this.isPolicyAttachedToRole(resource, res)
      );

      if (attachedRoles.length > 0) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a policy document contains IoT SiteWise actions
   */
  private hasIoTSiteWiseActions(policyDocument: any): boolean {
    const statements = policyDocument.Statement || [];

    if (!Array.isArray(statements)) {
      return false;
    }

    for (const statement of statements) {
      const action = statement.Action;

      // Handle Action as string
      if (typeof action === 'string') {
        if (action.startsWith('iotsitewise:') || action === 'iotsitewise:*') {
          return true;
        }
      }

      // Handle Action as array
      if (Array.isArray(action)) {
        for (const act of action) {
          if (typeof act === 'string' &&
            (act.startsWith('iotsitewise:') || act === 'iotsitewise:*')) {
            return true;
          }
        }
      }

      // Handle intrinsic functions with pattern matching
      if (containsPattern(action, 'iotsitewise:')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a policy is attached to a role
   */
  private isPolicyAttachedToRole(policy: CloudFormationResource, role: CloudFormationResource): boolean {
    // Check if policy is in role's ManagedPolicyArns
    const managedPolicyArns = role.Properties?.ManagedPolicyArns || [];
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (containsPattern(arn, policy.LogicalId)) {
          return true;
        }
      }
    }

    // Check if policy is in role's Policies
    const policies = role.Properties?.Policies || [];
    if (Array.isArray(policies)) {
      for (const p of policies) {
        if (p.PolicyName === policy.Properties?.PolicyName) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if an IAM policy has mixed user and admin permissions
   */
  private hasMixedPolicyPermissions(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    const policyDocument = resource.Properties?.PolicyDocument;

    if (!policyDocument) {
      return false;
    }

    const statements = policyDocument.Statement || [];

    let hasReadPermissions = false;
    let hasWritePermissions = false;

    if (Array.isArray(statements)) {
      for (const statement of statements) {
        const action = statement.Action;

        if (Array.isArray(action)) {
          for (const act of action) {
            if (typeof act === 'string') {
              if (act.includes('Get') ||
                act.includes('List') ||
                act.includes('Describe') ||
                act.includes(':Read')) {
                hasReadPermissions = true;
              }

              if (act.includes('Create') ||
                act.includes('Update') ||
                act.includes('Delete') ||
                act.includes('Put') ||
                act.includes(':Write')) {
                hasWritePermissions = true;
              }
            }
          }
        } else if (typeof action === 'string') {
          if (action.includes('Get') ||
            action.includes('List') ||
            action.includes('Describe') ||
            action.includes(':Read')) {
            hasReadPermissions = true;
          }

          if (action.includes('Create') ||
            action.includes('Update') ||
            action.includes('Delete') ||
            action.includes('Put') ||
            action.includes(':Write')) {
            hasWritePermissions = true;
          }
        }
      }
    }

    // Return true if the policy has both read and write permissions
    return hasReadPermissions && hasWritePermissions;
  }

  /**
   * Check if an IAM group is related to IoT SiteWise
   */
  private isIoTSiteWiseGroup(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Simple string-based detection (original implementation)
    const groupJson = JSON.stringify(resource.Properties || {});
    const simpleMatch = groupJson.includes('iotsitewise') ||
      groupJson.includes('IoTSiteWise') ||
      groupJson.includes('SiteWise');

    if (simpleMatch) {
      return true;
    }

    // Check for attached IoT SiteWise policies
    const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (containsPattern(arn, 'IoTSiteWise') ||
          containsPattern(arn, 'iotsitewise') ||
          containsPattern(arn, 'SiteWise')) {
          return true;
        }
      }
    }

    // Check for relationships with IoT SiteWise resources or roles
    if (allResources) {
      // Check if this group has attached policies related to IoT SiteWise
      const policies = allResources.filter(res =>
        res.Type === 'AWS::IAM::Policy' &&
        this.isIoTSiteWisePolicy(res, allResources)
      );

      for (const policy of policies) {
        if (this.isPolicyAttachedToGroup(policy, resource)) {
          return true;
        }
      }

      // Check if users in this group are admins for IoT SiteWise portals
      const portals = allResources.filter(res => res.Type === 'AWS::IoTSiteWise::Portal');
      for (const portal of portals) {
        const portalAdminUsers = portal.Properties?.PortalAdminUsers || [];
        if (Array.isArray(portalAdminUsers)) {
          for (const admin of portalAdminUsers) {
            if (containsPattern(admin, resource.LogicalId)) {
              return true;
            }
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if a policy is attached to a group
   */
  private isPolicyAttachedToGroup(policy: CloudFormationResource, group: CloudFormationResource): boolean {
    // Check if policy is in group's ManagedPolicyArns
    const managedPolicyArns = group.Properties?.ManagedPolicyArns || [];
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (containsPattern(arn, policy.LogicalId)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if an IAM group has mixed user and admin permissions
   */
  private hasGroupMixedPermissions(resource: CloudFormationResource): boolean {
    const managedPolicyArns = resource.Properties?.ManagedPolicyArns || [];

    let hasReadOnlyPolicy = false;
    let hasFullAccessPolicy = false;

    // Check managed policies
    if (Array.isArray(managedPolicyArns)) {
      for (const arn of managedPolicyArns) {
        if (typeof arn === 'string') {
          if (arn.includes('ReadOnly')) {
            hasReadOnlyPolicy = true;
          }

          if (arn.includes('FullAccess')) {
            hasFullAccessPolicy = true;
          }
        }
      }
    }

    // Return true if the group has both read-only and full access policies
    return hasReadOnlyPolicy && hasFullAccessPolicy;
  }
}

export default new IoT032Rule();
