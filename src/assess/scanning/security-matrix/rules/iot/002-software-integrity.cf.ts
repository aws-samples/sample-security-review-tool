import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT2 Rule: Periodically check the software integrity of IoT devices according to lifecycle policies.
 * 
 * Simplified to focus on verifiable CloudFormation elements:
 * - Code signing for IoT Jobs/JobTemplates
 * - Software integrity tracking attributes on IoT Things
 * - Basic integrity policy indicators on Thing Groups
 */
export class IoT002Rule extends BaseRule {
  constructor() {
    super(
      'IOT-002',
      'HIGH',
      'IoT resources lack software integrity verification mechanisms',
      [
        'AWS::IoT::Thing', 
        'AWS::IoT::ThingGroup', 
        'AWS::IoT::Job',
        'AWS::IoT::JobTemplate'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::IoT::Thing') {
      return this.evaluateIoTThing(resource, stackName);
    }

    if (resource.Type === 'AWS::IoT::ThingGroup') {
      return this.evaluateIoTThingGroup(resource, stackName);
    }

    if (resource.Type === 'AWS::IoT::Job' || resource.Type === 'AWS::IoT::JobTemplate') {
      return this.evaluateIoTJob(resource, stackName);
    }

    return null;
  }

  private evaluateIoTThing(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Only check for software integrity tracking attributes
    if (!this.hasSoftwareIntegrityAttributes(resource)) {
      const issueMessage = `${this.description} (missing software integrity tracking)`;
      const fix = 'Add attributes like softwareVersion, firmwareVersion, or signatureVerification to track software integrity';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }
    return null;
  }

  private evaluateIoTThingGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.hasGroupSoftwareIntegrityPolicy(resource)) {
      const issueMessage = `${this.description} (missing software integrity policy)`;
      const fix = 'Add integrity-related attributes or tags to the IoT thing group';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }
    return null;
  }

  private evaluateIoTJob(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.jobIncludesCodeSigning(resource)) {
      const issueMessage = `${this.description} (job lacks code signing)`;
      const fix = 'Configure IoT job to include code signing for software updates';
      return this.createScanResult(resource, stackName, issueMessage, fix);
    }
    return null;
  }


  private hasSoftwareIntegrityAttributes(resource: CloudFormationResource): boolean {
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    if (!attributes) return false;

    const integrityKeys = ['softwareversion', 'firmwareversion', 'signatureverification', 'integritycheck'];
    return Object.keys(attributes).some(key => 
      integrityKeys.some(attr => key.toLowerCase().includes(attr))
    );
  }

  private hasGroupSoftwareIntegrityPolicy(resource: CloudFormationResource): boolean {
    // Check attributes
    const attributes = resource.Properties?.ThingGroupProperties?.AttributePayload?.Attributes;
    if (attributes) {
      const hasIntegrityAttr = Object.keys(attributes).some(key => 
        key.toLowerCase().includes('integrity') || key.toLowerCase().includes('software')
      );
      if (hasIntegrityAttr) return true;
    }

    // Check tags
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      return tags.some(tag => 
        tag.Key && tag.Key.toLowerCase().includes('integrity') && tag.Value === 'true'
      );
    }

    return false;
  }

  private jobIncludesCodeSigning(resource: CloudFormationResource): boolean {
    const document = resource.Properties?.Document;
    if (!document) return false;
    
    // Check for code signing in job document
    if (document.CodeSigning) return true;
    if (document.operation === 'FIRMWARE_UPDATE' && document.files) {
      const filesStr = JSON.stringify(document.files);
      return filesStr.includes('signature') || filesStr.includes('checksum');
    }
    
    return false;
  }

  
}

export default new IoT002Rule();
