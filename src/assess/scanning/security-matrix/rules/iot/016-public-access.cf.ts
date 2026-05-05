import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT16 Rule: Block public access to IoT applications and implement authentication and authorization strategies.
 * 
 * Documentation: "Use X.509 certificate authentication when available. Otherwise, use IAM and Cognito authentication. 
 * See https://docs.aws.amazon.com/iot/latest/developerguide/authentication.html"
 */
export class IoT016Rule extends BaseRule {
  constructor() {
    super(
      'IOT-016',
      'HIGH',
      'IoT resources lack proper authentication and authorization controls',
      ['AWS::IoT::Policy', 'AWS::IoT::TopicRule', 'AWS::IoT::Authorizer', 'AWS::IoT::DomainConfiguration']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check for IoT Policies
    if (resource.Type === 'AWS::IoT::Policy') {
      // Check if the policy allows public access
      if (this.policyAllowsPublicAccess(resource)) {
        const issueMessage = `${this.description} (policy allows public access)`;
        const fix = 'Update the IoT policy to restrict access and require authentication';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Topic Rules
    if (resource.Type === 'AWS::IoT::TopicRule') {
      // Check if the topic rule has proper authentication
      if (!this.topicRuleHasAuthentication(resource)) {
        const issueMessage = `${this.description} (topic rule lacks proper authentication)`;
        const fix = 'Configure IoT topic rules to enforce authentication';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Authorizers
    if (resource.Type === 'AWS::IoT::Authorizer') {
      // Check if the authorizer is properly configured
      if (!this.authorizerIsProperlyConfigured(resource)) {
        const issueMessage = `${this.description} (authorizer not properly configured)`;
        const fix = 'Configure IoT authorizers with proper settings for authentication';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Domain Configurations
    if (resource.Type === 'AWS::IoT::DomainConfiguration') {
      // Check if the domain configuration has authentication
      if (!this.domainConfigurationHasAuthentication(resource)) {
        const issueMessage = `${this.description} (domain configuration lacks authentication)`;
        const fix = 'Configure IoT domain configurations with proper authentication';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    return null;
  }

  /**
   * Check if the IoT Policy allows public access
   */
  private policyAllowsPublicAccess(resource: CloudFormationResource): boolean {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (!policyDocument) {
      return false;
    }
    
    const policyJson = JSON.stringify(policyDocument);
    
    // Check if the policy has any overly permissive statements
    const hasWildcardResource = policyJson.includes('"Resource":"*"') || 
                               policyJson.includes('"Resource": "*"');
    
    // Check if the policy allows anonymous access
    const allowsAnonymousAccess = policyJson.includes('"Effect":"Allow"') && 
                                 !policyJson.includes('${iot:Connection.Thing.') && 
                                 !policyJson.includes('${iot:Certificate.') && 
                                 !policyJson.includes('${cognito-identity.amazonaws.com:');
    
    return hasWildcardResource && allowsAnonymousAccess;
  }

  /**
   * Check if the IoT Topic Rule has proper authentication
   */
  private topicRuleHasAuthentication(resource: CloudFormationResource): boolean {
    const sql = resource.Properties?.TopicRulePayload?.Sql;
    if (!sql) {
      return false;
    }
    
    // Check if the SQL statement includes authentication checks
    const hasAuthenticationCheck = sql.includes('clientid()') || 
                                 sql.includes('topic()') || 
                                 sql.includes('principal()');
    
    // Check if the rule has an authorizer
    const hasAuthorizer = resource.Properties?.TopicRulePayload?.AuthorizerName !== undefined;
    
    return hasAuthenticationCheck || hasAuthorizer;
  }

  /**
   * Check if the IoT Authorizer is properly configured
   */
  private authorizerIsProperlyConfigured(resource: CloudFormationResource): boolean {
    // Check if the authorizer has a status
    const status = resource.Properties?.Status;
    if (status !== 'ACTIVE') {
      return false;
    }
    
    // Check if the authorizer has a signing disabled flag
    const signingDisabled = resource.Properties?.SigningDisabled;
    if (signingDisabled === true) {
      return false;
    }
    
    // Check if the authorizer has a function ARN
    const functionArn = resource.Properties?.AuthorizerFunctionArn;
    if (!functionArn) {
      return false;
    }
    
    return true;
  }

  /**
   * Check if the IoT Domain Configuration has authentication
   */
  private domainConfigurationHasAuthentication(resource: CloudFormationResource): boolean {
    // Check if the domain configuration has authentication type
    const authenticationType = resource.Properties?.AuthenticationType;
    if (!authenticationType || authenticationType === 'NONE') {
      return false;
    }
    
    // Check if the domain configuration has server certificate ARN for custom authentication
    if (authenticationType === 'CUSTOM_AUTH' && !resource.Properties?.ServerCertificateArn) {
      return false;
    }
    
    // Check if the domain configuration has validation certificate for custom authentication
    if (authenticationType === 'CUSTOM_AUTH' && !resource.Properties?.ValidationCertificateArn) {
      return false;
    }
    
    return true;
  }
}

export default new IoT016Rule();
