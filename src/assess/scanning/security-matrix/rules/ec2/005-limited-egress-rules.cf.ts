import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import {
  hasIntrinsicFunction,
  containsPattern
} from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * EC25 Rule: Egress rules for instances limit outbound access to less than the entire Internet
 * 
 * Documentation: "Generally speaking, if an instance has a path to the Internet, it should not have 
 * unrestricted access to all ports and all IP addresses. Either a NACL, egress rule, or other mechanism 
 * like a routing table should limit the Internet addresses and ports that an instance can reach."
 * 
 * Note: This functionality is partially covered by Checkov rule:
 * - CKV_AWS_260: Ensure no security groups allow egress to 0.0.0.0/0 on all ports
 * 
 * This rule adds additional logic to allow common ports like HTTP/HTTPS/DNS to the internet.
 */
export class EC2005Rule extends BaseRule {
  constructor() {
    super(
      'EC2-005',
      'MEDIUM',
      'Security group allows unrestricted outbound access to the entire Internet',
      ['AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupEgress']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      // Check if the security group has explicit egress rules
      const securityGroupEgress = resource.Properties?.SecurityGroupEgress;

      // If no egress rules are specified, the default is to allow all outbound traffic
      if (!securityGroupEgress) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add explicit egress rules to the security group that restrict outbound traffic to specific IP ranges and ports required by the application.`
        );
      }

      // Handle different representations of egress rules
      if (Array.isArray(securityGroupEgress)) {
        // Empty array means no egress rules, which is the same as allowing all traffic
        if (securityGroupEgress.length === 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Add explicit egress rules to the security group that restrict outbound traffic to specific IP ranges and ports required by the application.`
          );
        }

        // Check each egress rule in the array
        for (const egress of securityGroupEgress) {
          if (this.isOverlyPermissiveEgress(egress)) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Restrict egress rules to specific IP ranges and ports required by the application instead of allowing all traffic to 0.0.0.0/0 or ::/0.`
            );
          }
        }
      } else if (hasIntrinsicFunction(securityGroupEgress)) {
        // Handle intrinsic functions like Ref, GetAtt, etc.
        // For CDK-generated templates, we need to check if the reference might be overly permissive
        if (this.mightBeOverlyPermissiveReference(securityGroupEgress)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Ensure that referenced egress rules restrict outbound traffic to specific IP ranges and ports required by the application.`
          );
        }
      } else {
        // Handle other cases (like CDK tokens) by checking for patterns
        const egressStr = JSON.stringify(securityGroupEgress);
        if (this.containsOverlyPermissivePattern(egressStr)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Restrict egress rules to specific IP ranges and ports required by the application instead of allowing all traffic to 0.0.0.0/0 or ::/0.`
          );
        }
      }
    }

    if (resource.Type === 'AWS::EC2::SecurityGroupEgress') {
      if (this.isOverlyPermissiveEgress(resource.Properties)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Restrict egress rules to specific IP ranges and ports required by the application instead of allowing all traffic to 0.0.0.0/0 or ::/0.`
        );
      }
    }

    return null;
  }

  private isOverlyPermissiveEgress(egress: any): boolean {
    if (!egress) return false;

    // Handle intrinsic functions
    if (hasIntrinsicFunction(egress)) {
      return this.mightBeOverlyPermissiveReference(egress);
    }

    // Check if the egress rule allows traffic to 0.0.0.0/0 or ::/0
    const hasUnrestrictedIpv4 = this.hasUnrestrictedIpv4(egress);
    const hasUnrestrictedIpv6 = this.hasUnrestrictedIpv6(egress);

    if (!hasUnrestrictedIpv4 && !hasUnrestrictedIpv6) {
      return false;
    }

    // Check if this is already covered by Checkov rule CKV_AWS_260
    // Checkov checks for egress to 0.0.0.0/0 on all ports
    const protocol = this.resolveProtocol(egress.IpProtocol);
    const fromPort = this.resolvePort(egress.FromPort);
    const toPort = this.resolvePort(egress.ToPort);

    // If protocol is -1 (all) or ports are very wide range, Checkov will catch this
    if (protocol === '-1' || protocol === 'all' ||
      (fromPort <= 0 && toPort >= 65535)) {
      return false;
    }

    // Allow common HTTP/HTTPS ports to the internet
    if (protocol === 'tcp') {
      // Allow HTTP
      if (fromPort === 80 && toPort === 80) {
        return false;
      }

      // Allow HTTPS
      if (fromPort === 443 && toPort === 443) {
        return false;
      }
    }

    // Allow DNS (UDP port 53) to the internet
    if (protocol === 'udp' && fromPort === 53 && toPort === 53) {
      return false;
    }

    // Allow DNS (TCP port 53) to the internet
    if (protocol === 'tcp' && fromPort === 53 && toPort === 53) {
      return false;
    }

    // All other unrestricted egress rules are considered overly permissive
    return true;
  }

  /**
   * Check if an egress rule allows unrestricted IPv4 access
   */
  private hasUnrestrictedIpv4(egress: any): boolean {
    // Direct string check
    if (egress.CidrIp === '0.0.0.0/0') {
      return true;
    }

    // Check for intrinsic functions
    if (hasIntrinsicFunction(egress.CidrIp) &&
      containsPattern(egress.CidrIp, /0\.0\.0\.0\/0/)) {
      return true;
    }

    // Check for CDK tokens
    const cidrStr = JSON.stringify(egress.CidrIp || {});
    return cidrStr.includes('0.0.0.0/0') ||
      cidrStr.toLowerCase().includes('anyipv4') ||
      cidrStr.toLowerCase().includes('allipv4');
  }

  /**
   * Check if an egress rule allows unrestricted IPv6 access
   */
  private hasUnrestrictedIpv6(egress: any): boolean {
    // Direct string check
    if (egress.CidrIpv6 === '::/0') {
      return true;
    }

    // Check for intrinsic functions
    if (hasIntrinsicFunction(egress.CidrIpv6) &&
      containsPattern(egress.CidrIpv6, /::\/(0)/)) {
      return true;
    }

    // Check for CDK tokens
    const cidrStr = JSON.stringify(egress.CidrIpv6 || {});
    return cidrStr.includes('::/0') ||
      cidrStr.toLowerCase().includes('anyipv6') ||
      cidrStr.toLowerCase().includes('allipv6');
  }

  /**
   * Resolve the protocol from a value that might be an intrinsic function
   */
  private resolveProtocol(protocol: any): string {
    if (typeof protocol === 'string') {
      return protocol.toLowerCase();
    }

    // Handle intrinsic functions
    if (hasIntrinsicFunction(protocol)) {
      const protocolStr = JSON.stringify(protocol);
      if (protocolStr.toLowerCase().includes('tcp')) return 'tcp';
      if (protocolStr.toLowerCase().includes('udp')) return 'udp';
      if (protocolStr.toLowerCase().includes('icmp')) return 'icmp';
    }

    return '';
  }

  /**
   * Resolve a port number from a value that might be an intrinsic function
   */
  private resolvePort(port: any): number {
    // Direct number
    if (typeof port === 'number') {
      return port;
    }

    // String that can be parsed as a number
    if (typeof port === 'string') {
      const parsedPort = parseInt(port, 10);
      if (!isNaN(parsedPort)) {
        return parsedPort;
      }
    }

    // Handle intrinsic functions
    if (hasIntrinsicFunction(port)) {
      const portStr = JSON.stringify(port);

      // Look for common port numbers in the string
      if (portStr.includes('80')) return 80;
      if (portStr.includes('443')) return 443;
      if (portStr.includes('53')) return 53;
      if (portStr.includes('22')) return 22;
      if (portStr.includes('3306')) return 3306;
      if (portStr.includes('5432')) return 5432;
    }

    return -1;
  }

  /**
   * Check if a reference might be to an overly permissive egress rule
   */
  private mightBeOverlyPermissiveReference(value: any): boolean {
    // Convert to string for pattern matching
    const valueStr = JSON.stringify(value);

    return this.containsOverlyPermissivePattern(valueStr);
  }

  /**
   * Check if a string contains patterns indicating overly permissive egress rules
   */
  private containsOverlyPermissivePattern(str: string): boolean {
    // Check for unrestricted CIDR patterns
    if (str.includes('0.0.0.0/0') || str.includes('::/0')) {
      return true;
    }

    // Check for CDK patterns indicating unrestricted access
    const permissivePatterns = [
      'anyipv4',
      'anyipv6',
      'allipv4',
      'allipv6',
      'allowall',
      'unrestricted',
      'opentoworld',
      'opentoall',
      'alloweverything',
      'allowalloutbound',
      'allowalltraffic'
    ];

    // Check if the string contains any of the permissive patterns
    const lowerStr = str.toLowerCase();
    return permissivePatterns.some(pattern => lowerStr.includes(pattern));
  }
}

export default new EC2005Rule();
