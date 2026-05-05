import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';


/**
 * IoT1 Rule: Manage IoT device visibility and alert on exceptions. Assign an owner to act on alerts.
 * 
 * Documentation: "The visibility of the IoT devices needs to be managed. Are they managed by these?
 * 1. AWS IoT device registry
 * 2. AWS IoT Device Management Fleet hub
 * 3. Customer provided IoT device/asset management"
 */
export class IoT001Rule extends BaseRule {
  constructor() {
    super(
      'IOT-001',
      'HIGH',
      'IoT resources lack proper visibility management or alerting mechanisms',
      ['AWS::IoT::Thing', 'AWS::IoT::ThingGroup', 'AWS::IoT::Policy']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if the resource is an IoT resource
    if (!this.isIoTResource(resource)) {
      return null;
    }



    // For IoT Things, check for proper visibility management
    if (resource.Type === 'AWS::IoT::Thing') {
      // Check for essential requirements
      const hasDeviceRegistry = this.hasDeviceRegistry(resource);
      const hasFleetHub = this.hasFleetManagement(resource, allResources);
      const hasAlerting = this.hasAlertingConfigured(resource, allResources);
      const hasOwnership = this.hasOwnershipAssigned(resource, allResources);
      
      // Device registry is a fundamental requirement
      if (!hasDeviceRegistry) {
        // If device registry is missing, check if we have at least two of the other requirements
        if ((hasFleetHub && hasAlerting) || 
            (hasFleetHub && hasOwnership) || 
            (hasAlerting && hasOwnership)) {
          // If we have at least two other requirements, it's acceptable
          return null;
        }
        
        // Otherwise, flag the issue
        const issueMessage = `${this.description} (not properly registered in AWS IoT device registry)`;
        const fix = 'Ensure IoT devices are properly registered in AWS IoT device registry';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
      
      // If device registry is present, check if we have at least one of the other requirements
      if (hasFleetHub || hasAlerting || hasOwnership) {
        // If we have at least one other requirement, it's acceptable
        return null;
      }
      
      // If we only have device registry but none of the other requirements, flag the issue
      const issues = [];
      if (!hasFleetHub) issues.push('not integrated with AWS IoT Device Management Fleet Hub');
      if (!hasAlerting) issues.push('missing alerting mechanisms for exceptions');
      if (!hasOwnership) issues.push('no owner assigned to act on alerts');
      
      const issueMessage = `${this.description} (${issues.join(', ')})`;
      const fix = 'Ensure IoT devices have at least one of: Fleet Hub integration, alerting mechanisms, or ownership assignment'
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // For IoT ThingGroups, check for proper management
    if (resource.Type === 'AWS::IoT::ThingGroup') {
      // First check for Fleet Hub integration
      const hasFleetHub = this.hasFleetManagement(resource, allResources);
      
      // If Fleet Hub integration is present, we don't need to check for ownership
      if (hasFleetHub) {
        return null; // Pass the check if Fleet Hub integration is present
      }
      
      // If no Fleet Hub integration, check for ownership as an alternative
      const hasOwnership = this.hasOwnershipAssigned(resource, allResources);
      if (hasOwnership) {
        return null; // Pass the check if ownership is assigned
      }
      
      // If neither Fleet Hub integration nor ownership is present, flag the issue
      const issueMessage = `${this.description} (not integrated with AWS IoT Device Management Fleet Hub, no owner assigned to act on alerts)`;
      const fix = 'Ensure IoT thing groups are integrated with Fleet Hub or have an owner assigned';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }

    // For IoT Policies, check for proper management
    if (resource.Type === 'AWS::IoT::Policy') {
      // For policies, we'll make all checks optional
      // Only check for ownership if we want to provide a recommendation
      const hasOwnership = this.hasOwnershipAssigned(resource, allResources);
      
      // If there's no ownership but we have Fleet Hub references in the policy, it's still valid
      if (!hasOwnership && !this.policyReferencesFleetHub(resource)) {
        const issueMessage = `${this.description} (no owner assigned to act on alerts). Action: Consider adding ownership information to IoT policies.`;
        // Return null instead of an issue since this is just a recommendation
        return null;
      }
    }

    return null;
  }
  
  /**
   * Check if a policy references Fleet Hub
   */
  private policyReferencesFleetHub(resource: CloudFormationResource): boolean {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (policyDocument) {
      const policyJson = JSON.stringify(policyDocument);
      return policyJson.includes('FleetHub') || 
             policyJson.includes('fleet') || 
             policyJson.includes('device-management');
    }
    return false;
  }

  /**
   * Check if the resource is an IoT resource
   */
  private isIoTResource(resource: CloudFormationResource): boolean {
    return [
      'AWS::IoT::Thing',
      'AWS::IoT::ThingGroup',
      'AWS::IoT::Policy'
    ].includes(resource.Type);
  }

  /**
   * Check if the IoT Thing is properly registered in AWS IoT device registry
   */
  private hasDeviceRegistry(resource: CloudFormationResource): boolean {
    // Check if the Thing has required attributes for proper registration
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    if (!attributes) {
      return false;
    }

    // Check for essential attributes that indicate proper registration
    const essentialAttributes = ['manufacturer', 'model', 'serialNumber', 'deviceType'];
    const attributeKeys = Object.keys(attributes);
    
    // Check if at least one essential attribute is present
    return essentialAttributes.some(attr => attributeKeys.includes(attr));
  }

  /**
   * Check if the IoT resource is integrated with Fleet Hub
   */
  private hasFleetManagement(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Check for Fleet Hub integration via attributes (for Things)
    if (resource.Type === 'AWS::IoT::Thing') {
      const attributes = resource.Properties?.AttributePayload?.Attributes;
      if (attributes) {
        const attributeKeys = Object.keys(attributes);
        // Check for fleetId attribute
        if (attributeKeys.includes('fleetId')) {
          return true;
        }
        
        // Check for fleetHubManaged attribute
        if (attributeKeys.includes('fleetHubManaged') && 
            this.isValueTrue(attributes.fleetHubManaged)) {
          return true;
        }
        
        // Check for managedBy attribute that includes FleetHub
        if (attributeKeys.includes('managedBy') && 
            typeof attributes.managedBy === 'string' && 
            attributes.managedBy.includes('FleetHub')) {
          return true;
        }
      }
    }
    
    // For Thing Groups, check naming conventions
    if (resource.Type === 'AWS::IoT::ThingGroup') {
      const thingGroupName = resource.Properties?.ThingGroupName || resource.LogicalId;
      
      // Check naming convention
      if (typeof thingGroupName === 'string' && 
          (thingGroupName.toLowerCase().includes('fleet') || 
           thingGroupName.toLowerCase().includes('managed'))) {
        return true;
      }
      
      // Check Thing Group properties
      const thingGroupProperties = resource.Properties?.ThingGroupProperties;
      if (thingGroupProperties) {
        const thingGroupPropertiesStr = JSON.stringify(thingGroupProperties);
        if (thingGroupPropertiesStr.toLowerCase().includes('fleet') || 
            thingGroupPropertiesStr.toLowerCase().includes('managed')) {
          return true;
        }
      }
      
      // Check if any Things in this group have Fleet Hub attributes
      if (allResources) {
        const thingsInGroup = this.findThingsInGroup(thingGroupName, allResources);
        if (thingsInGroup.some(thing => this.thingHasFleetHubAttributes(thing))) {
          return true;
        }
      }
    }
    
    // For Policies, check if they reference Fleet Hub
    if (resource.Type === 'AWS::IoT::Policy') {
      if (this.policyReferencesFleetHub(resource)) {
        return true;
      }
    }

    // Check for Fleet Hub integration via tags (as a fallback)
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      // Check for Fleet Hub related tags (case-insensitive)
      if (tags.some(tag => {
        const key = tag.Key?.toLowerCase();
        const value = typeof tag.Value === 'string' ? tag.Value.toLowerCase() : '';
        
        return (key === 'fleethubmanaged' && this.isValueTrue(tag.Value)) || 
               (key === 'managedby' && value.includes('fleethub')) ||
               (key === 'fleetid') ||
               (key?.includes('fleet') && this.isValueTrue(tag.Value));
      })) {
        return true;
      }
    }

    return false;
  }
  
  /**
   * Helper method to check if a value represents a boolean true
   */
  private isValueTrue(value: any): boolean {
    if (typeof value === 'boolean') {
      return value;
    }
    
    if (typeof value === 'string') {
      const trueValues = ['true', 'yes', '1', 't', 'y'];
      return trueValues.includes(value.toLowerCase());
    }
    
    if (typeof value === 'number') {
      return value === 1;
    }
    
    return false;
  }
  
  /**
   * Find Things that belong to a specific Thing Group
   */
  private findThingsInGroup(groupName: string, allResources: CloudFormationResource[]): CloudFormationResource[] {
    return allResources.filter(res => {
      if (res.Type === 'AWS::IoT::Thing') {
        // Check for direct group membership
        const thingGroupsProperty = res.Properties?.ThingGroups;
        if (Array.isArray(thingGroupsProperty) && 
            thingGroupsProperty.some(group => 
              typeof group === 'string' && 
              (group === groupName || group.includes(groupName))
            )) {
          return true;
        }
        
        // Check for thing-group attachments
        return allResources.some(attachment => 
          attachment.Type === 'AWS::IoT::ThingPrincipalAttachment' &&
          attachment.Properties?.ThingName === (res.Properties?.ThingName || res.LogicalId) &&
          attachment.Properties?.Principal?.includes(groupName)
        );
      }
      return false;
    });
  }
  
  /**
   * Check if a Thing has Fleet Hub related attributes
   */
  private thingHasFleetHubAttributes(thing: CloudFormationResource): boolean {
    const attributes = thing.Properties?.AttributePayload?.Attributes;
    if (!attributes) return false;
    
    const attributeKeys = Object.keys(attributes);
    return attributeKeys.includes('fleetId') || 
           (attributeKeys.includes('fleetHubManaged') && this.isValueTrue(attributes.fleetHubManaged)) ||
           (attributeKeys.includes('managedBy') && 
            typeof attributes.managedBy === 'string' && 
            attributes.managedBy.includes('FleetHub'));
  }

  /**
   * Check if alerting is configured for the IoT resource
   */
  private hasAlertingConfigured(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const resourceName = resource.Properties?.ThingName || resource.LogicalId;
    const resourceType = resource.Type;
    const resourceJson = JSON.stringify(resource);
    
    // Check for CloudWatch alarms or EventBridge rules referencing this IoT resource
    const hasDirectAlertingMechanism = allResources.some(res => {
      // Check CloudWatch alarms
      if (res.Type === 'AWS::CloudWatch::Alarm') {
        const alarmProperties = JSON.stringify(res.Properties || {});
        return alarmProperties.includes(resourceName) || 
               (resourceType === 'AWS::IoT::Thing' && alarmProperties.includes('IoT'));
      }
      
      // Check EventBridge rules
      if (res.Type === 'AWS::Events::Rule') {
        const ruleProperties = JSON.stringify(res.Properties || {});
        return (ruleProperties.includes('iot') || ruleProperties.includes('IoT')) && 
               (ruleProperties.includes(resourceName) || ruleProperties.includes('*'));
      }
      
      // Check IoT topic rules
      if (res.Type === 'AWS::IoT::TopicRule') {
        const ruleProperties = JSON.stringify(res.Properties || {});
        return ruleProperties.includes(resourceName) || 
               (resourceType === 'AWS::IoT::Thing' && 
                (ruleProperties.includes('thing/+/shadow') || 
                 ruleProperties.includes('thing/#')));
      }
      
      // Check AWS IoT Device Defender
      if (res.Type === 'AWS::IoT::SecurityProfile') {
        const profileProperties = JSON.stringify(res.Properties || {});
        const targets = res.Properties?.Targets;
        
        // Check if this security profile targets all things or this specific thing
        if (Array.isArray(targets)) {
          return targets.some(target => 
            target === '*' || 
            target.includes(resourceName) || 
            target.includes('all/things')
          );
        }
        
        // Check if the security profile mentions this resource
        return profileProperties.includes(resourceName);
      }
      
      // Check AWS IoT Events detector models
      if (res.Type === 'AWS::IoTEvents::DetectorModel') {
        const modelProperties = JSON.stringify(res.Properties || {});
        return modelProperties.includes('iot') && 
               (modelProperties.includes(resourceName) || modelProperties.includes('*'));
      }
      
      return false;
    });
    
    // Check if the resource itself has monitoring configurations
    const hasInternalMonitoring = resourceJson.includes('monitoring') || 
                                 resourceJson.includes('alert') || 
                                 resourceJson.includes('notification');
    
    // Check if there's a Lambda function that might be monitoring this resource
    const hasLambdaMonitoring = allResources.some(res => 
      res.Type === 'AWS::Lambda::Function' && 
      JSON.stringify(res.Properties || {}).includes('iot') && 
      (JSON.stringify(res.Properties || {}).includes(resourceName) || 
       JSON.stringify(res.Properties || {}).includes('monitoring'))
    );
    
    return hasDirectAlertingMechanism || hasInternalMonitoring || hasLambdaMonitoring;
  }

  /**
   * Check if ownership is assigned to the IoT resource
   */
  private hasOwnershipAssigned(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Check for ownership attributes (for Things)
    if (resource.Type === 'AWS::IoT::Thing') {
      const attributes = resource.Properties?.AttributePayload?.Attributes;
      if (attributes) {
        if (Object.keys(attributes).some(key => 
          ['owner', 'team', 'responsibleparty', 'contact', 'email', 'oncall', 
           'responsible', 'maintainer', 'department', 'project'].includes(key.toLowerCase())
        )) {
          return true;
        }
      }
    }
    
    // Check resource name for ownership indicators
    const resourceName = this.getResourceName(resource);
    if (resourceName && this.nameIndicatesOwnership(resourceName)) {
      return true;
    }
    
    // Check for related IAM roles with ownership information
    if (allResources) {
      const relatedRoles = this.findRelatedIamRoles(resource, allResources);
      if (relatedRoles.some(role => this.roleIndicatesOwnership(role))) {
        return true;
      }
      
      // Check for resource policies that might indicate ownership
      const relatedPolicies = this.findRelatedResourcePolicies(resource, allResources);
      if (relatedPolicies.length > 0) {
        return true;
      }
    }
    
    // Check for ownership tags (as a fallback)
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      if (tags.some(tag => {
        const key = tag.Key?.toLowerCase();
        return ['owner', 'team', 'responsibleparty', 'contact', 'email', 'oncall', 
                'responsible', 'maintainer', 'department', 'project'].includes(key || '');
      })) {
        return true;
      }
    }

    return false;
  }
  
  /**
   * Get the resource name from different resource types
   */
  private getResourceName(resource: CloudFormationResource): string | null {
    if (resource.Type === 'AWS::IoT::Thing') {
      return resource.Properties?.ThingName || resource.LogicalId;
    } else if (resource.Type === 'AWS::IoT::ThingGroup') {
      return resource.Properties?.ThingGroupName || resource.LogicalId;
    } else if (resource.Type === 'AWS::IoT::Policy') {
      return resource.Properties?.PolicyName || resource.LogicalId;
    }
    return resource.LogicalId;
  }
  
  /**
   * Check if a name indicates ownership
   */
  private nameIndicatesOwnership(name: string): boolean {
    const ownershipPrefixes = ['team-', 'dept-', 'project-', 'owner-', 'owned-by-', 'maintained-by-'];
    const ownershipKeywords = ['team', 'department', 'project', 'owner', 'owned', 'maintained'];
    
    const nameLower = name.toLowerCase();
    
    // Check for prefixes
    if (ownershipPrefixes.some(prefix => nameLower.startsWith(prefix))) {
      return true;
    }
    
    // Check for keywords in the name
    if (ownershipKeywords.some(keyword => nameLower.includes(keyword))) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Find IAM roles related to this resource
   */
  private findRelatedIamRoles(resource: CloudFormationResource, allResources: CloudFormationResource[]): CloudFormationResource[] {
    const resourceName = this.getResourceName(resource);
    return allResources.filter(res => 
      res.Type === 'AWS::IAM::Role' && 
      (JSON.stringify(res.Properties?.AssumeRolePolicyDocument || {}).includes('iot') ||
       JSON.stringify(res.Properties || {}).includes(resourceName || ''))
    );
  }
  
  /**
   * Check if an IAM role indicates ownership
   */
  private roleIndicatesOwnership(role: CloudFormationResource): boolean {
    // Check role name for ownership indicators
    const roleName = role.Properties?.RoleName || role.LogicalId;
    if (typeof roleName === 'string' && this.nameIndicatesOwnership(roleName)) {
      return true;
    }
    
    // Check role description for ownership indicators
    const description = role.Properties?.Description;
    if (typeof description === 'string' && 
        (description.toLowerCase().includes('team') || 
         description.toLowerCase().includes('owner') || 
         description.toLowerCase().includes('responsible'))) {
      return true;
    }
    
    // Check role tags for ownership indicators
    const tags = role.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      if (tags.some(tag => {
        const key = tag.Key?.toLowerCase();
        return ['owner', 'team', 'responsibleparty', 'contact', 'email', 'oncall'].includes(key || '');
      })) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Find resource policies related to this resource
   */
  private findRelatedResourcePolicies(resource: CloudFormationResource, allResources: CloudFormationResource[]): CloudFormationResource[] {
    const resourceName = this.getResourceName(resource);
    return allResources.filter(res => 
      (res.Type === 'AWS::IoT::Policy' || 
       res.Type === 'AWS::IAM::Policy' || 
       res.Type === 'AWS::IAM::ManagedPolicy') && 
      JSON.stringify(res.Properties || {}).includes(resourceName || '')
    );
  }
}

export default new IoT001Rule();
