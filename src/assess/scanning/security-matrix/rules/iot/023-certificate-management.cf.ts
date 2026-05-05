import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

class IoT023Rule extends BaseRule {
  constructor() {
    super(
      'IOT-023',
      'HIGH',
      'IoT device certificate management not properly configured',
      [
        'AWS::IoT::Certificate',
        'AWS::IoT::Thing',
        'AWS::IoT::Policy'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) {
      return null;
    }

    if (!allResources) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (cannot verify certificate configuration)`,
        `Configure certificate lifecycle management with rotation and revocation capabilities.`
      );
    }

    const resolver = new CloudFormationResolver(allResources);

    switch (resource.Type) {
      case 'AWS::IoT::Certificate':
        return this.evaluateCertificate(resource, stackName, resolver);
      case 'AWS::IoT::Thing':
        return this.evaluateThing(resource, stackName, resolver);
      case 'AWS::IoT::Policy':
        return this.evaluatePolicy(resource, stackName, resolver);
    }

    return null;
  }

  private evaluateCertificate(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    const issues = [];

    // Check if certificate has proper status management
    const status = resource.Properties?.Status;
    if (!status || status === 'PENDING_ACTIVATION') {
      issues.push('certificate status not properly managed');
    }

    // Check for certificate rotation mechanism
    if (!this.hasCertificateRotation(resolver)) {
      issues.push('no certificate rotation mechanism configured');
    }

    if (issues.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (${issues[0]})`,
        `Configure certificate lifecycle management with proper status and rotation.`
      );
    }

    return null;
  }

  private evaluateThing(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    // Check if thing has associated certificates
    const certificates = resolver.getResourcesByType('AWS::IoT::Certificate');
    const thingPrincipals = resolver.getResourcesByType('AWS::IoT::ThingPrincipalAttachment');

    const hasAssociatedCertificate = thingPrincipals.some(attachment => {
      const thingName = resolver.resolve(attachment.Properties?.ThingName);
      return thingName.referencedResources.includes(resource.LogicalId);
    });

    if (!hasAssociatedCertificate && certificates.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no certificates associated with thing)`,
        `Associate certificates with IoT things for secure authentication.`
      );
    }

    return null;
  }

  private evaluatePolicy(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (!policyDocument) return null;

    const policyStr = JSON.stringify(policyDocument).toLowerCase();

    // Check if policy includes certificate management permissions
    const hasCertManagement = policyStr.includes('iot:createcertificate') ||
      policyStr.includes('iot:updatecertificate') ||
      policyStr.includes('iot:deletecertificate');

    if (hasCertManagement && !policyStr.includes('condition')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (certificate management policy lacks conditions)`,
        `Add conditions to certificate management policies for security.`
      );
    }

    return null;
  }

  private hasCertificateRotation(resolver: CloudFormationResolver): boolean {
    // Check for Lambda functions that handle certificate rotation
    const lambdaFunctions = resolver.getResourcesByType('AWS::Lambda::Function');
    const hasRotationLambda = lambdaFunctions.some(lambda => {
      const code = JSON.stringify(lambda.Properties?.Code || {}).toLowerCase();
      return code.includes('certificate') && (code.includes('rotate') || code.includes('renewal'));
    });

    // Check for EventBridge rules for certificate expiration
    const eventRules = resolver.getResourcesByType('AWS::Events::Rule');
    const hasExpirationRule = eventRules.some(rule => {
      const eventPattern = JSON.stringify(rule.Properties?.EventPattern || {}).toLowerCase();
      return eventPattern.includes('certificate') && eventPattern.includes('expir');
    });

    return hasRotationLambda || hasExpirationRule;
  }
}

const iot023RuleInstance = new IoT023Rule();
export { IoT023Rule };
export default iot023RuleInstance;