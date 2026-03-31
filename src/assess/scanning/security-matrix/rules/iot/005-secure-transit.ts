import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * IoT5 Rule: Secure all data in transit among IoT Devices and cloud systems.
 * 
 * Documentation: "Secure cloud connections need to be enforced to prevent malware from infecting your IoT devices:
 * 1. Prohibit connections from IoT devices to unknown network endpoints.
 * 2. Limit outbound connections and monitor using AWS IoT Device Defender.
 * 3. Use Firewall on devices to limit inbound & outbound connections.
 * 4. Close inbound ports and use only port 443 for outbound traffic.
 * 5. Prefer VPC endpoints when available.
 * 6. Use TLS proxy when connecting to public cloud endpoints.
 * 7. Discourage IoT Devices listening for any incoming connections."
 */
export class IoT005Rule extends BaseRule {
  constructor() {
    super(
      'IOT-005',
      'HIGH',
      'IoT resources lack secure data transit configurations',
      ['AWS::IoT::Thing', 'AWS::IoT::Policy', 'AWS::IoT::TopicRule', 'AWS::IoT::SecurityProfile']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check for IoT Things
    if (resource.Type === 'AWS::IoT::Thing') {
      const issues = [];

      // Check for secure transit attributes
      if (!this.hasSecureTransitAttributes(resource)) {
        issues.push('missing secure transit attributes');
      }

      // If any issues were found, create a scan result
      if (issues.length > 0) {
        const issueMessage = `${this.description} (${issues.join(', ')})`;
        const fix = 'Configure secure data transit for IoT devices using TLS, VPC endpoints, and proper port restrictions';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Policies
    if (resource.Type === 'AWS::IoT::Policy') {
      // Check if the policy enforces secure connections
      if (!this.policyEnforcesSecureConnections(resource)) {
        const issueMessage = `${this.description} (policy does not enforce secure connections)`;
        const fix = 'Update the IoT policy to enforce TLS connections and restrict to known endpoints';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Topic Rules
    if (resource.Type === 'AWS::IoT::TopicRule') {
      // Check if the topic rule uses secure endpoints
      if (!this.topicRuleUsesSecureEndpoints(resource)) {
        const issueMessage = `${this.description} (topic rule does not use secure endpoints)`;
        const fix = 'Configure IoT topic rules to use secure endpoints and VPC endpoints where available';
        return this.createScanResult(resource, stackName, issueMessage, fix);
      }
    }

    // Check for IoT Security Profiles
    if (resource.Type === 'AWS::IoT::SecurityProfile') {
      // Check if the security profile monitors for insecure connections
      if (!this.securityProfileMonitorsConnections(resource)) {
        const issueMessage = `${this.description} (security profile does not monitor for insecure connections)`;
        const fix = 'Configure IoT Device Defender security profiles to monitor for unauthorized connections';
        return this.createScanResult(resource, stackName, issueMessage);
      }
    }

    return null;
  }

  /**
   * Check if the IoT Thing has attributes related to secure transit
   */
  private hasSecureTransitAttributes(resource: CloudFormationResource): boolean {
    const attributes = resource.Properties?.AttributePayload?.Attributes;
    if (!attributes) {
      return false;
    }

    // Check for attributes related to secure transit
    const secureTransitAttributes = [
      'tlsEnabled',
      'secureConnectionsOnly',
      'port443Only',
      'useVpcEndpoint',
      'firewallEnabled',
      'noInboundConnections'
    ];

    return Object.keys(attributes).some(key => 
      secureTransitAttributes.some(attr => key.toLowerCase().includes(attr.toLowerCase()))
    );
  }

  /**
   * Check if the IoT Policy enforces secure connections
   */
  private policyEnforcesSecureConnections(resource: CloudFormationResource): boolean {
    const policyDocument = resource.Properties?.PolicyDocument;
    if (!policyDocument) {
      return false;
    }
    
    const policyJson = JSON.stringify(policyDocument);
    
    // Check if the policy has any deny statements for insecure connections
    const hasDenyForInsecureConnections = policyJson.includes('"Effect":"Deny"') && 
                                         (policyJson.includes('mqtt:Connect') || 
                                          policyJson.includes('iot:Connect')) && 
                                         policyJson.includes('aws:SecureTransport');
    
    // Check if the policy restricts to known endpoints
    const restrictsToKnownEndpoints = policyJson.includes('aws:SourceIp') || 
                                     policyJson.includes('aws:SourceVpc') || 
                                     policyJson.includes('aws:SourceVpce');
    
    // Check if the policy enforces TLS
    const enforcesTls = policyJson.includes('aws:SecureTransport') && 
                       policyJson.includes('true');
    
    return hasDenyForInsecureConnections || (restrictsToKnownEndpoints && enforcesTls);
  }

  /**
   * Check if the IoT Topic Rule uses secure endpoints
   */
  private topicRuleUsesSecureEndpoints(resource: CloudFormationResource): boolean {
    const actions = resource.Properties?.TopicRulePayload?.Actions;
    if (!actions || !Array.isArray(actions) || actions.length === 0) {
      return false;
    }
    
    // Check if any action uses insecure endpoints
    const hasInsecureEndpoint = actions.some(action => {
      const actionJson = JSON.stringify(action);
      
      // Check for HTTP actions without HTTPS
      if (actionJson.includes('Http') && !actionJson.includes('https://')) {
        return true;
      }
      
      // Check for Lambda actions without VPC configuration
      if (actionJson.includes('Lambda') && !actionJson.includes('VpcConfig')) {
        // This is a simplification - not all Lambda functions need VPC config
        // but for IoT devices, it's generally a good practice
        return false;
      }
      
      return false;
    });
    
    return !hasInsecureEndpoint;
  }

  /**
   * Check if the IoT Security Profile monitors for insecure connections
   */
  private securityProfileMonitorsConnections(resource: CloudFormationResource): boolean {
    const behaviors = resource.Properties?.Behaviors;
    if (!behaviors || !Array.isArray(behaviors) || behaviors.length === 0) {
      return false;
    }
    
    // Check for behaviors that monitor connections
    return behaviors.some(behavior => {
      const behaviorJson = JSON.stringify(behavior);
      
      return behaviorJson.includes('Ports') || 
             behaviorJson.includes('Destinations') || 
             behaviorJson.includes('Connection') || 
             behaviorJson.includes('Protocol');
    });
  }
}

export default new IoT005Rule();
