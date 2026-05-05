import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import {
  hasIntrinsicFunction,
} from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * EC23 Rule: No security groups allow 0.0.0.0/0 inbound access
 * 
 * Documentation: "The vast majority of ProServe work is in non-production environments and, 
 * generally speaking, internet-accessible resources should not live in dev/test/non-prod environments. 
 * Only when an instance is intended to be public AND it lives in a production environment should 
 * security groups permit connections from all IP ranges."
 * 
 * Note: This functionality is partially covered by Checkov rules:
 * - CKV_AWS_24: Ensure security group rule does not allow ingress from 0.0.0.0/0 to port 22
 * - CKV_AWS_25: Ensure security group rule does not allow ingress from 0.0.0.0/0 to port 3389
 * 
 * This rule is more restrictive as it checks for any inbound access from 0.0.0.0/0, not just SSH and RDP ports.
 */
export class EC2003Rule extends BaseRule {
  constructor() {
    super(
      'EC2-003',
      'HIGH',
      'Security group allows unrestricted inbound access from 0.0.0.0/0',
      ['AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupIngress']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check security group rules for overly permissive access

    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      const securityGroupIngress = resource.Properties?.SecurityGroupIngress;

      if (securityGroupIngress && Array.isArray(securityGroupIngress)) {
        for (const ingress of securityGroupIngress) {
          if (this.isOpenToWorld(ingress)) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Restrict ingress rules to specific IP ranges instead of 0.0.0.0/0 or ::/0. If this is a production environment and the instance must be public, consider using a load balancer instead of direct access.`
            );
          }
        }
      }
    }

    if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
      if (this.isOpenToWorld(resource.Properties)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Restrict ingress rules to specific IP ranges instead of 0.0.0.0/0 or ::/0. If this is a production environment and the instance must be public, consider using a load balancer instead of direct access.`
        );
      }
    }

    return null;
  }

  private isOpenToWorld(ingress: any): boolean {
    // Check for direct string values
    if (ingress.CidrIp === '0.0.0.0/0' || ingress.CidrIpv6 === '::/0') {
      // Check if this is already covered by Checkov
      const port = this.getPortValue(ingress.FromPort);
      if (port === 22 || port === 3389) {
        // Skip this check as it's already covered by Checkov rules
        // CKV_AWS_24 (port 22) or CKV_AWS_25 (port 3389)
        return false;
      }
      return true;
    }

    // Handle intrinsic functions in CidrIp
    if (ingress.CidrIp && typeof ingress.CidrIp === 'object') {
      // Handle Ref
      if (ingress.CidrIp.Ref) {
        // We can't determine the value of the reference at static analysis time
        // Check if the parameter name suggests it might be open to the world
        const refName = ingress.CidrIp.Ref;
        if (typeof refName === 'string' &&
          (refName.toLowerCase().includes('any') ||
            refName.toLowerCase().includes('all') ||
            refName.toLowerCase().includes('public') ||
            refName.toLowerCase().includes('open'))) {
          return true;
        }
      }

      // Handle Fn::Join
      if (ingress.CidrIp['Fn::Join'] && Array.isArray(ingress.CidrIp['Fn::Join'])) {
        const joinParts = ingress.CidrIp['Fn::Join'][1];
        if (Array.isArray(joinParts)) {
          const joinedValue = joinParts.join('');
          if (joinedValue.includes('0.0.0.0/0')) {
            return true;
          }
        }
      }

      // Handle Fn::Sub
      if (ingress.CidrIp['Fn::Sub']) {
        const subValue = typeof ingress.CidrIp['Fn::Sub'] === 'string' ?
          ingress.CidrIp['Fn::Sub'] :
          (Array.isArray(ingress.CidrIp['Fn::Sub']) ? ingress.CidrIp['Fn::Sub'][0] : '');

        if (subValue.includes('0.0.0.0/0')) {
          return true;
        }
      }

      // Check stringified object for patterns
      const cidrStr = JSON.stringify(ingress.CidrIp);
      if (cidrStr.includes('0.0.0.0/0')) {
        return true;
      }
    }

    // Handle intrinsic functions in CidrIpv6
    if (ingress.CidrIpv6 && typeof ingress.CidrIpv6 === 'object') {
      // Handle Ref
      if (ingress.CidrIpv6.Ref) {
        // We can't determine the value of the reference at static analysis time
        // Check if the parameter name suggests it might be open to the world
        const refName = ingress.CidrIpv6.Ref;
        if (typeof refName === 'string' &&
          (refName.toLowerCase().includes('any') ||
            refName.toLowerCase().includes('all') ||
            refName.toLowerCase().includes('public') ||
            refName.toLowerCase().includes('open'))) {
          return true;
        }
      }

      // Handle Fn::Join
      if (ingress.CidrIpv6['Fn::Join'] && Array.isArray(ingress.CidrIpv6['Fn::Join'])) {
        const joinParts = ingress.CidrIpv6['Fn::Join'][1];
        if (Array.isArray(joinParts)) {
          const joinedValue = joinParts.join('');
          if (joinedValue.includes('::/0')) {
            return true;
          }
        }
      }

      // Handle Fn::Sub
      if (ingress.CidrIpv6['Fn::Sub']) {
        const subValue = typeof ingress.CidrIpv6['Fn::Sub'] === 'string' ?
          ingress.CidrIpv6['Fn::Sub'] :
          (Array.isArray(ingress.CidrIpv6['Fn::Sub']) ? ingress.CidrIpv6['Fn::Sub'][0] : '');

        if (subValue.includes('::/0')) {
          return true;
        }
      }

      // Check stringified object for patterns
      const cidrStr = JSON.stringify(ingress.CidrIpv6);
      if (cidrStr.includes('::/0')) {
        return true;
      }
    }

    // Handle CidrBlock property (sometimes used instead of CidrIp)
    if (ingress.CidrBlock === '0.0.0.0/0') {
      return true;
    }

    // Handle intrinsic functions in CidrBlock
    if (ingress.CidrBlock && typeof ingress.CidrBlock === 'object') {
      // Similar checks as for CidrIp
      const cidrStr = JSON.stringify(ingress.CidrBlock);
      if (cidrStr.includes('0.0.0.0/0')) {
        return true;
      }
    }

    // Handle Ipv6CidrBlock property (sometimes used instead of CidrIpv6)
    if (ingress.Ipv6CidrBlock === '::/0') {
      return true;
    }

    // Handle intrinsic functions in Ipv6CidrBlock
    if (ingress.Ipv6CidrBlock && typeof ingress.Ipv6CidrBlock === 'object') {
      // Similar checks as for CidrIpv6
      const cidrStr = JSON.stringify(ingress.Ipv6CidrBlock);
      if (cidrStr.includes('::/0')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get the numeric value of a port, handling intrinsic functions
   */
  private getPortValue(port: any): number {
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
      if (portStr.includes('22') || portStr.toLowerCase().includes('ssh')) return 22;
      if (portStr.includes('3389') || portStr.toLowerCase().includes('rdp')) return 3389;
      if (portStr.includes('80')) return 80;
      if (portStr.includes('443')) return 443;
    }

    return -1;
  }
}

export default new EC2003Rule();
