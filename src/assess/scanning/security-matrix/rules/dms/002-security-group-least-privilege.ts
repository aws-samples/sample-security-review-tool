import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * DMS2: Restrict traffic among DMS replication instance Security Groups by least privilege
 * 
 * Security Principle: Principle of Least Privilege & Deny-by-Default
 * 
 * This rule ensures that DMS replication instance security groups follow least privilege
 * principles and deny-by-default access patterns.
 * 
 * Risk: Overly permissive security groups increase attack surface and enable
 * unauthorized access to DMS resources.
 */
export class DMS002Rule extends BaseRule {
    constructor() {
        super(
            'DMS-002',
            'HIGH',
            'DMS security group violates least privilege principles',
            ['AWS::DMS::ReplicationInstance', 'AWS::EC2::SecurityGroup']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (resource.Type === 'AWS::DMS::ReplicationInstance') {
            return this.evaluateReplicationInstance(resource, stackName, allResources);
        }
        
        if (resource.Type === 'AWS::EC2::SecurityGroup') {
            return this.evaluateSecurityGroup(resource, stackName, allResources);
        }
        
        return null;
    }

    private evaluateReplicationInstance(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        const securityGroupIds = resource.Properties?.VpcSecurityGroupIds;
        if (!securityGroupIds || !Array.isArray(securityGroupIds)) return null;

        // Check if any referenced security groups are overly permissive
        for (const sgId of securityGroupIds) {
            const sg = this.findSecurityGroup(sgId, allResources);
            if (sg && this.hasOverlyPermissiveRules(sg)) {
                return this.createScanResult(
                    resource,
                    stackName,
                    this.description,
                    'Restrict security group rules to specific ports, protocols, and CIDR blocks required for DMS operations.'
                );
            }
        }

        return null;
    }

    private evaluateSecurityGroup(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        // Only check security groups that are used by DMS replication instances
        if (!this.isUsedByDMSInstance(resource, allResources)) return null;

        if (this.hasOverlyPermissiveRules(resource)) {
            return this.createScanResult(
                resource,
                stackName,
                this.description,
                'Restrict security group rules to specific ports, protocols, and CIDR blocks required for DMS operations.'
            );
        }

        return null;
    }

    private findSecurityGroup(sgId: any, allResources?: CloudFormationResource[]): CloudFormationResource | null {
        if (!allResources) return null;

        const resolver = new CloudFormationResolver(allResources);
        const resolvedSgId = resolver.resolve<string>(sgId);

        if (!resolvedSgId.isResolved) return null;

        // Find security group by logical ID or by matching GroupId property
        return allResources.find(resource => 
            resource.Type === 'AWS::EC2::SecurityGroup' && 
            (resource.LogicalId === resolvedSgId.value || 
             resource.Properties?.GroupId === resolvedSgId.value)
        ) || null;
    }

    private isUsedByDMSInstance(securityGroup: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
        if (!allResources) return false;

        return allResources.some(resource => {
            if (resource.Type !== 'AWS::DMS::ReplicationInstance') return false;
            
            const securityGroupIds = resource.Properties?.VpcSecurityGroupIds || [];
            return securityGroupIds.some((sgId: any) => {
                const resolver = new CloudFormationResolver(allResources);
                const resolvedSgId = resolver.resolve<string>(sgId);
                
                return resolvedSgId.isResolved && 
                       (resolvedSgId.value === securityGroup.LogicalId ||
                        resolvedSgId.value === securityGroup.Properties?.GroupId);
            });
        });
    }

    private isOverlyPermissiveEgress(rule: any): boolean {
        // Flag egress 0.0.0.0/0 with all protocols/ports - DMS shouldn't need arbitrary outbound
        if ((rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0') && 
            (rule.IpProtocol === '-1' || (rule.FromPort === 0 && rule.ToPort === 65535))) {
            return true;
        }

        return false;
    }

    private isOverlyPermissive(rule: any): boolean {
        // Flag all protocols (-1) - DMS only needs TCP
        if (rule.IpProtocol === '-1') return true;

        // Flag all ports (0-65535) - ports should be constrained
        if (rule.FromPort === 0 && rule.ToPort === 65535) return true;

        // Flag ingress 0.0.0.0/0 - exposes instance to internet
        if (rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0') {
            return true;
        }

        return false;
    }

    private hasOverlyPermissiveRules(securityGroup: CloudFormationResource): boolean {
        const ingress = securityGroup.Properties?.SecurityGroupIngress || [];
        const egress = securityGroup.Properties?.SecurityGroupEgress || [];

        // Check ingress rules for overly permissive patterns
        const hasPermissiveIngress = ingress.some((rule: any) => this.isOverlyPermissive(rule));
        
        // Check egress rules for overly permissive patterns
        const hasPermissiveEgress = egress.some((rule: any) => 
            this.isOverlyPermissive(rule) || this.isOverlyPermissiveEgress(rule)
        );

        return hasPermissiveIngress || hasPermissiveEgress;
    }
}

export default new DMS002Rule();