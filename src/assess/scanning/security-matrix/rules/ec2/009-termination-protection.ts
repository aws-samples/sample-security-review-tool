import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import {
  hasIntrinsicFunction,
  containsPattern,
  isReferenceToResource,
  extractResourceIdsFromReference
} from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * EC29 Rule: Is termination protection enabled for instances outside of an ASG?
 * 
 * Documentation: "Solutions with EC2 instances provisioned outside of the AWS Auto Scaling Groups (ASGs) 
 * must have Termination Protection safety feature enabled in order to protect the instances from being 
 * accidentally terminated."
 * 
 * Note: Basic termination protection check is covered by Checkov rule:
 * - CKV_AWS_48: Ensure EC2 instance has termination protection enabled
 * 
 * This rule adds additional logic to exclude instances that are part of Auto Scaling Groups.
 */
export class EC2009Rule extends BaseRule {
  constructor() {
    super(
      'EC2-009',
      'MEDIUM',
      'EC2 instance outside of an Auto Scaling Group does not have termination protection enabled',
      ['AWS::EC2::Instance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::EC2::Instance') {
      // Check if the instance has termination protection enabled
      const disableApiTermination = resource.Properties?.DisableApiTermination;

      if (!this.isTerminationProtectionEnabled(disableApiTermination)) {
        // Check if this instance might be part of an Auto Scaling Group
        const isPartOfAsg = this.isInstancePartOfAsg(resource, allResources);

        if (!isPartOfAsg) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set the DisableApiTermination property to true for the EC2 instance to enable termination protection.`
          );
        }
      }
    }

    return null;
  }

  /**
   * Check if termination protection is enabled, handling intrinsic functions and CDK tokens
   * @param disableApiTermination The value to check
   * @returns True if termination protection is enabled, false otherwise
   */
  private isTerminationProtectionEnabled(disableApiTermination: any): boolean {
    // Direct boolean check
    if (disableApiTermination === true) {
      return true;
    }

    // Handle string values that might represent true
    if (typeof disableApiTermination === 'string' &&
      (disableApiTermination.toLowerCase() === 'true' || disableApiTermination === '1')) {
      return true;
    }

    // Handle intrinsic functions
    if (hasIntrinsicFunction(disableApiTermination)) {
      // Check for patterns indicating true in the intrinsic function
      if (containsPattern(disableApiTermination, /true|1|enabled|protect/i)) {
        return true;
      }

      // Check for specific parameter references that might be true
      const terminationStr = JSON.stringify(disableApiTermination);
      if (terminationStr.includes('TerminationProtection') ||
        terminationStr.includes('DisableApiTermination') ||
        terminationStr.includes('ProtectInstance')) {
        return true;
      }
    }

    // Handle CDK tokens
    if (disableApiTermination && typeof disableApiTermination === 'object') {
      const terminationStr = JSON.stringify(disableApiTermination);

      // Check for CDK tokens
      if (terminationStr.includes('TOKEN[') || terminationStr.includes('CDK')) {
        // Check for patterns indicating termination protection is enabled
        if (terminationStr.toLowerCase().includes('true') ||
          terminationStr.toLowerCase().includes('enabled') ||
          terminationStr.toLowerCase().includes('protect')) {
          return true;
        }

        // Check for common CDK termination protection parameter names
        const protectionPatterns = [
          'terminationprotection',
          'disableapitermination',
          'protectinstance',
          'preventtermination',
          'instanceprotection'
        ];

        const lowerStr = terminationStr.toLowerCase();
        if (protectionPatterns.some(pattern => lowerStr.includes(pattern))) {
          // If the token contains protection-related terms, assume it's enabled
          return true;
        }
      }
    }

    return false;
  }

  private isInstancePartOfAsg(instance: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // If allResources is not provided, we can't check cross-resource references
    if (!allResources) {
      return false;
    }

    // Check if the instance has metadata that indicates it's part of an ASG
    const metadata = (instance as any).Metadata;
    if (metadata && typeof metadata === 'object') {
      const metadataStr = JSON.stringify(metadata).toLowerCase();
      if (metadataStr.includes('autoscaling') || metadataStr.includes('aws:autoscaling')) {
        return true;
      }
    }

    // Check for ASG-related patterns in the instance properties
    const instanceJson = JSON.stringify(instance);
    if (instanceJson.toLowerCase().includes('autoscaling') ||
      instanceJson.toLowerCase().includes('asg') ||
      instanceJson.toLowerCase().includes('aws:autoscaling')) {
      return true;
    }

    // Check if the instance is referenced by an ASG
    const asgResources = allResources.filter(r => r.Type === 'AWS::AutoScaling::AutoScalingGroup');

    // Check if the instance is in a subnet that's used by an ASG
    const instanceSubnet = instance.Properties?.SubnetId;

    if (instanceSubnet) {
      for (const asg of asgResources) {
        const vpcZoneIdentifier = asg.Properties?.VPCZoneIdentifier;

        if (this.resourcesShareSubnet(instanceSubnet, vpcZoneIdentifier)) {
          return true;
        }
      }
    }

    // Check if the instance uses a launch template or launch configuration that's also used by an ASG
    const instanceImageId = instance.Properties?.ImageId;
    const instanceInstanceType = instance.Properties?.InstanceType;

    if (instanceImageId && instanceInstanceType) {
      for (const asg of asgResources) {
        // Check launch configuration
        if (this.matchesLaunchConfiguration(asg, instance, instanceImageId, instanceInstanceType, allResources)) {
          return true;
        }

        // Check launch template
        if (this.matchesLaunchTemplate(asg, instance, instanceImageId, instanceInstanceType, allResources)) {
          return true;
        }
      }
    }

    // Check for CDK-specific patterns
    const instanceStr = JSON.stringify(instance);
    if (instanceStr.includes('TOKEN[') || instanceStr.includes('CDK')) {
      // Check for ASG-related patterns in the instance
      if (this.containsAsgPattern(instanceStr)) {
        return true;
      }

      // Check if any ASG might reference this instance through CDK tokens
      for (const asg of asgResources) {
        const asgStr = JSON.stringify(asg);
        if ((asgStr.includes('TOKEN[') || asgStr.includes('CDK')) &&
          this.mightBeRelated(instanceStr, asgStr)) {
          return true;
        }
      }
    }

    return false;
  }


  /**
   * Check if an instance subnet is included in an ASG's VPCZoneIdentifier
   */
  private resourcesShareSubnet(instanceSubnet: any, vpcZoneIdentifier: any): boolean {
    // Direct string comparison
    if (typeof vpcZoneIdentifier === 'string' && typeof instanceSubnet === 'string') {
      return vpcZoneIdentifier.includes(instanceSubnet);
    }

    // Array comparison
    if (Array.isArray(vpcZoneIdentifier)) {
      if (typeof instanceSubnet === 'string') {
        return vpcZoneIdentifier.some(subnet =>
          typeof subnet === 'string' && subnet.includes(instanceSubnet)
        );
      }
    }

    // Handle intrinsic functions and CDK tokens
    if (hasIntrinsicFunction(vpcZoneIdentifier) || hasIntrinsicFunction(instanceSubnet)) {
      const vpcStr = JSON.stringify(vpcZoneIdentifier);
      const subnetStr = JSON.stringify(instanceSubnet);

      // Check for direct references
      if (isReferenceToResource(vpcZoneIdentifier, instanceSubnet) ||
        isReferenceToResource(instanceSubnet, vpcZoneIdentifier)) {
        return true;
      }

      // Extract resource IDs and check for matches
      const vpcIds = extractResourceIdsFromReference(vpcZoneIdentifier);
      const subnetIds = extractResourceIdsFromReference(instanceSubnet);

      for (const vpcId of vpcIds) {
        for (const subnetId of subnetIds) {
          if (vpcId === subnetId || vpcId.includes(subnetId) || subnetId.includes(vpcId)) {
            return true;
          }
        }
      }

      // Check for CDK tokens
      if ((vpcStr.includes('TOKEN[') || vpcStr.includes('CDK')) &&
        (subnetStr.includes('TOKEN[') || subnetStr.includes('CDK'))) {
        // If both are CDK tokens, check for common patterns
        return this.mightBeRelated(vpcStr, subnetStr);
      }
    }

    return false;
  }

  /**
   * Check if an instance matches a launch configuration used by an ASG
   */
  private matchesLaunchConfiguration(
    asg: CloudFormationResource,
    instance: CloudFormationResource,
    instanceImageId: any,
    instanceInstanceType: any,
    allResources: CloudFormationResource[]
  ): boolean {
    const launchConfigName = asg.Properties?.LaunchConfigurationName;
    if (!launchConfigName) return false;

    // Handle direct reference
    if (typeof launchConfigName === 'string') {
      const launchConfig = allResources.find(r =>
        r.Type === 'AWS::AutoScaling::LaunchConfiguration' && r.LogicalId === launchConfigName
      );

      if (launchConfig) {
        // Check if image ID and instance type match
        if (this.valuesMatch(launchConfig.Properties?.ImageId, instanceImageId) &&
          this.valuesMatch(launchConfig.Properties?.InstanceType, instanceInstanceType)) {
          return true;
        }
      }
    }

    // Handle intrinsic functions and CDK tokens
    if (hasIntrinsicFunction(launchConfigName) ||
      (typeof launchConfigName === 'object' &&
        JSON.stringify(launchConfigName).includes('TOKEN['))) {

      // Find all launch configurations
      const launchConfigs = allResources.filter(r =>
        r.Type === 'AWS::AutoScaling::LaunchConfiguration'
      );

      // Check each launch configuration
      for (const launchConfig of launchConfigs) {
        if (isReferenceToResource(launchConfigName, launchConfig.LogicalId || '')) {
          // Check if image ID and instance type match
          if (this.valuesMatch(launchConfig.Properties?.ImageId, instanceImageId) &&
            this.valuesMatch(launchConfig.Properties?.InstanceType, instanceInstanceType)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if an instance matches a launch template used by an ASG
   */
  private matchesLaunchTemplate(
    asg: CloudFormationResource,
    instance: CloudFormationResource,
    instanceImageId: any,
    instanceInstanceType: any,
    allResources: CloudFormationResource[]
  ): boolean {
    const launchTemplate = asg.Properties?.LaunchTemplate;
    if (!launchTemplate) return false;

    const launchTemplateId = launchTemplate.LaunchTemplateId || launchTemplate.LaunchTemplateName;
    if (!launchTemplateId) return false;

    // Handle direct reference
    if (typeof launchTemplateId === 'string') {
      const launchTemplateResource = allResources.find(r =>
        r.Type === 'AWS::EC2::LaunchTemplate' &&
        (r.LogicalId === launchTemplateId || r.Properties?.LaunchTemplateName === launchTemplateId)
      );

      if (launchTemplateResource) {
        const ltData = launchTemplateResource.Properties?.LaunchTemplateData;
        if (ltData) {
          // Check if image ID and instance type match
          if (this.valuesMatch(ltData.ImageId, instanceImageId) &&
            this.valuesMatch(ltData.InstanceType, instanceInstanceType)) {
            return true;
          }
        }
      }
    }

    // Handle intrinsic functions and CDK tokens
    if (hasIntrinsicFunction(launchTemplateId) ||
      (typeof launchTemplateId === 'object' &&
        JSON.stringify(launchTemplateId).includes('TOKEN['))) {

      // Find all launch templates
      const launchTemplates = allResources.filter(r =>
        r.Type === 'AWS::EC2::LaunchTemplate'
      );

      // Check each launch template
      for (const launchTemplate of launchTemplates) {
        if (isReferenceToResource(launchTemplateId, launchTemplate.LogicalId || '') ||
          isReferenceToResource(launchTemplateId, launchTemplate.Properties?.LaunchTemplateName || '')) {

          const ltData = launchTemplate.Properties?.LaunchTemplateData;
          if (ltData) {
            // Check if image ID and instance type match
            if (this.valuesMatch(ltData.ImageId, instanceImageId) &&
              this.valuesMatch(ltData.InstanceType, instanceInstanceType)) {
              return true;
            }
          }
        }
      }
    }

    return false;
  }

  /**
   * Check if two values match, handling intrinsic functions and CDK tokens
   */
  private valuesMatch(value1: any, value2: any): boolean {
    // Direct equality
    if (value1 === value2) return true;

    // Handle string values
    if (typeof value1 === 'string' && typeof value2 === 'string') {
      return value1.includes(value2) || value2.includes(value1);
    }

    // Handle intrinsic functions
    if (hasIntrinsicFunction(value1) || hasIntrinsicFunction(value2)) {
      // Check for direct references
      if (isReferenceToResource(value1, value2) || isReferenceToResource(value2, value1)) {
        return true;
      }

      // Extract resource IDs and check for matches
      const ids1 = extractResourceIdsFromReference(value1);
      const ids2 = extractResourceIdsFromReference(value2);

      for (const id1 of ids1) {
        for (const id2 of ids2) {
          if (id1 === id2 || id1.includes(id2) || id2.includes(id1)) {
            return true;
          }
        }
      }
    }

    // Handle CDK tokens
    const str1 = JSON.stringify(value1);
    const str2 = JSON.stringify(value2);

    if ((str1.includes('TOKEN[') || str1.includes('CDK')) &&
      (str2.includes('TOKEN[') || str2.includes('CDK'))) {
      return this.mightBeRelated(str1, str2);
    }

    return false;
  }

  /**
   * Check if a string contains patterns indicating it's related to an ASG
   */
  private containsAsgPattern(str: string): boolean {
    const asgPatterns = [
      'autoscalinggroup',
      'autoscaling',
      'asg',
      'scalinggroup',
      'aws:autoscaling',
      'autoScalingGroupName'
    ];

    const lowerStr = str.toLowerCase();
    return asgPatterns.some(pattern => lowerStr.includes(pattern));
  }

  /**
   * Check if two CDK token strings might be related
   */
  private mightBeRelated(str1: string, str2: string): boolean {
    // Extract common identifiers from CDK tokens
    const extractIdentifiers = (str: string): string[] => {
      const identifiers: string[] = [];

      // Extract logical IDs
      const logicalIdMatches = str.match(/LogicalId[^:]*:([^,}]+)/g) || [];
      identifiers.push(...logicalIdMatches.map(m => m.replace(/LogicalId[^:]*:([^,}]+)/g, '$1').trim().replace(/['"]/g, '')));

      // Extract resource IDs
      const resourceMatches = str.match(/Resource:([^,}]+)/g) || [];
      identifiers.push(...resourceMatches.map(m => m.replace(/Resource:([^,}]+)/g, '$1').trim().replace(/['"]/g, '')));

      // Extract stack names
      const stackMatches = str.match(/Stack:([^,}]+)/g) || [];
      identifiers.push(...stackMatches.map(m => m.replace(/Stack:([^,}]+)/g, '$1').trim().replace(/['"]/g, '')));

      return identifiers.filter(Boolean);
    };

    const ids1 = extractIdentifiers(str1);
    const ids2 = extractIdentifiers(str2);

    // Check for matching identifiers
    for (const id1 of ids1) {
      for (const id2 of ids2) {
        if (id1 === id2 || id1.includes(id2) || id2.includes(id1)) {
          return true;
        }
      }
    }

    // Check for common patterns
    const commonPatterns = ['autoscaling', 'asg', 'instance', 'template', 'launch'];
    const lowerStr1 = str1.toLowerCase();
    const lowerStr2 = str2.toLowerCase();

    for (const pattern of commonPatterns) {
      if (lowerStr1.includes(pattern) && lowerStr2.includes(pattern)) {
        return true;
      }
    }

    return false;
  }
}

export default new EC2009Rule();
