import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT11 Rule: Ensure that each IoT device has a unique identity.
 * 
 * Documentation: "Every device must have a unique identifier to simplify development and auditing. 
 * Prefer the use of device-specific IoT certificates with private keys generated on-device, 
 * within a secure element in the device."
 */
export class IoT011Rule extends BaseRule {
  constructor() {
    super(
      'IOT-011',
      'HIGH',
      'IoT resources lack unique identity mechanisms',
      ['AWS::IoT::Thing', 'AWS::IoT::Certificate', 'AWS::IoT::Policy']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check for IoT Things
    if (resource.Type === 'AWS::IoT::Thing') {
      const issues = [];

      // Check for unique identity attributes
      if (!this.hasUniqueIdentityAttributes(resource)) {
        issues.push('missing unique identity attributes');
      }

      // Check for certificate association
      if (!this.hasCertificateAssociation(resource, allResources)) {
        issues.push('no X.509 certificate association');
      }

      // If any issues were found, create a scan result
      if (issues.length > 0) {
        const issueMessage = `${this.description} (${issues.join(', ')})`;
        const fix = 'Ensure IoT devices have unique identifiers and are associated with X.509 certificates';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Certificates
    if (resource.Type === 'AWS::IoT::Certificate') {
      // Check if the certificate is properly configured
      if (!this.isCertificateProperlyConfigured(resource)) {
        const issueMessage = `${this.description} (certificate not properly configured)`;
        const fix = 'Configure IoT certificates with proper settings for device identity';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Policies
    if (resource.Type === 'AWS::IoT::Policy') {
      // Check if the policy enforces unique identity
      if (!this.policyEnforcesUniqueIdentity(resource)) {
        const issueMessage = `${this.description} (policy does not enforce unique identity)`;
        const fix = 'Update the IoT policy to enforce unique identity for devices';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    return null;
  }

  /**
   * Check if the IoT Thing has attributes related to unique identity
   */
  private hasUniqueIdentityAttributes(resource: CloudFormationResource): boolean {
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    if (!attributes) {
      return false;
    }

    // Check for attributes related to unique identity
    const uniqueIdentityAttributes = [
      'serialNumber',
      'deviceId',
      'uniqueId',
      'macAddress',
      'uuid'
    ];

    return Object.keys(attributes).some(key =>
      uniqueIdentityAttributes.some(attr => key.toLowerCase().includes(attr.toLowerCase()))
    );
  }

  /**
   * Check if the IoT Thing is associated with a certificate
   */
  private hasCertificateAssociation(resource: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const thingName = resource.Properties?.ThingName || resource.LogicalId;

    // Check for AWS IoT ThingPrincipalAttachment resources that associate this thing with a certificate
    return allResources.some(res => {
      if (res.Type === 'AWS::IoT::ThingPrincipalAttachment') {
        const attachedThingName = res.Properties?.ThingName;
        const principal = res.Properties?.Principal;

        // Check if the attachment is for this thing and references a certificate
        return attachedThingName === thingName &&
          (principal?.includes('cert/') || principal?.includes('certificate'));
      }
      return false;
    });
  }

  /**
   * Check if the IoT Certificate is properly configured
   */
  private isCertificateProperlyConfigured(resource: CloudFormationResource): boolean {
    // Check if the certificate is active
    const status = resource.Properties?.Status;
    if (status !== 'ACTIVE') {
      return false;
    }

    // Check certificate properties
    const certificateSigningRequest = resource.Properties?.CertificateSigningRequest;
    const certificatePem = resource.Properties?.CertificatePem;

    // Either a CSR or a PEM must be provided
    if (!certificateSigningRequest && !certificatePem) {
      return false;
    }

    return true;
  }

  /**
   * Check if the IoT Policy enforces unique identity
   */
  private policyEnforcesUniqueIdentity(resource: CloudFormationResource): boolean {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (!policyDocument) {
      return false;
    }

    const policyJson = JSON.stringify(policyDocument);

    // Check if the policy uses variables that enforce unique identity
    return policyJson.includes('${iot:Connection.Thing.ThingName}') ||
      policyJson.includes('${iot:ClientId}') ||
      policyJson.includes('${iot:Certificate.ID}');
  }
}

export default new IoT011Rule();
