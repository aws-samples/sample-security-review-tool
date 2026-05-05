import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * IoT-024 Rule: Use certificate revocation lists to manage compromised or revoked certificates
 * 
 * Documentation: AWS IoT requires robust certificate management including proper handling
 * of compromised or revoked certificates. This rule checks for:
 * - Proper CA certificate configurations with revocation settings
 * - Certificate revocation checking mechanisms via CRL or OCSP
 * - Appropriate IAM policies for certificate revocation management
 * - Conditions on policies that allow certificate operations
 * 
 * See https://docs.aws.amazon.com/iot/latest/developerguide/device-certs-revoke.html
 */
export class IoT024Rule extends BaseRule {
  constructor() {
    super(
      'IOT-024',
      'HIGH',
      'Certificate revocation management not properly configured',
      [
        'AWS::IoT::CACertificate',
        'AWS::IoT::Certificate',
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
        `${this.description} (cannot verify revocation configuration)`,
        `Configure certificate revocation lists and revocation checking.`
      );
    }

    const resolver = new CloudFormationResolver(allResources);

    switch (resource.Type) {
      case 'AWS::IoT::CACertificate':
        return this.evaluateCACertificate(resource, stackName, resolver);
      case 'AWS::IoT::Certificate':
        return this.evaluateCertificate(resource, stackName, resolver);
      case 'AWS::IoT::Policy':
        return this.evaluatePolicy(resource, stackName, resolver);
    }

    return null;
  }

  private evaluateCACertificate(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    const issues = [];

    // Check if CA certificate has revocation configuration
    const registrationConfig = resource.Properties?.RegistrationConfig;
    if (!registrationConfig) {
      issues.push('no registration configuration for CA certificate');
    }

    // Check for revocation checking mechanism
    if (!this.hasRevocationChecking(resolver)) {
      issues.push('no certificate revocation checking configured');
    }

    if (issues.length > 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (${issues[0]})`,
        `Configure CA certificate with revocation checking and CRL endpoints.`
      );
    }

    return null;
  }

  private evaluateCertificate(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    // Check if there's a CA certificate that can manage revocation
    const caCertificates = resolver.getResourcesByType('AWS::IoT::CACertificate');

    if (caCertificates.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no CA certificate for revocation management)`,
        `Configure CA certificate to manage certificate revocation.`
      );
    }

    return null;
  }

  private evaluatePolicy(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (!policyDocument) return null;

    const policyStr = JSON.stringify(policyDocument).toLowerCase();

    // Check if policy includes revocation management permissions
    const hasRevocationPerms = policyStr.includes('iot:updatecacertificate') ||
      policyStr.includes('iot:setdefaultauthorizer') ||
      policyStr.includes('iot:updatecertificate');

    if (hasRevocationPerms && !this.hasRevocationConditions(policyDocument)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (revocation policy lacks proper conditions)`,
        `Add conditions to revocation policies for security.`
      );
    }

    return null;
  }

  private hasRevocationChecking(resolver: CloudFormationResolver): boolean {
    // Check for Lambda functions that handle revocation checking
    const lambdaFunctions = resolver.getResourcesByType('AWS::Lambda::Function');
    const hasRevocationLambda = lambdaFunctions.some(lambda => {
      const code = JSON.stringify(lambda.Properties?.Code || {}).toLowerCase();
      return code.includes('revocation') || code.includes('crl') || code.includes('ocsp');
    });

    // Check for custom resources that configure revocation
    const customResources = resolver.getResourcesByType('AWS::CloudFormation::CustomResource');
    const hasRevocationCustomResource = customResources.some(resource => {
      const properties = JSON.stringify(resource.Properties || {}).toLowerCase();
      return properties.includes('revocation') || properties.includes('crl');
    });

    return hasRevocationLambda || hasRevocationCustomResource;
  }

  private hasRevocationConditions(policyDocument: any): boolean {
    const statements = policyDocument.Statement || [];
    return statements.some((stmt: any) =>
      stmt.Condition && (
        stmt.Condition.StringEquals ||
        stmt.Condition.StringLike ||
        stmt.Condition.Bool
      )
    );
  }
}

export default new IoT024Rule();
