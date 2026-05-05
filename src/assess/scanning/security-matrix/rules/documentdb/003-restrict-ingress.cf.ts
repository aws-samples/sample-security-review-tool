import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class DocumentDB003Rule extends BaseRule {
    constructor() {
        super(
            'DOCDB-003',
            'HIGH',
            'DocumentDB cluster security groups allow unrestricted ingress from 0.0.0.0/0',
            ['AWS::DocDB::DBCluster']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const resolver = new CloudFormationResolver(allResources);

        const vpcSecurityGroupIds = resource.Properties?.VpcSecurityGroupIds;

        if (!vpcSecurityGroupIds) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `DocumentDB cluster does not specify VpcSecurityGroupIds and will use the default VPC security group, which may allow unrestricted access. Explicitly configure VpcSecurityGroupIds with properly secured security groups that restrict access to specific CIDR blocks or source security groups.`
            );
        }

        const resolved = resolver.resolve(vpcSecurityGroupIds, {
            treatLiteralStringsAs: 'external-references'
        });

        if (!resolved.isResolved) {
            return this.createScanResult(
                resource,
                stackName,
                'Security groups cannot be validated - use !Ref to resources defined in template'
            );
        }

        const sgIds = Array.isArray(resolved.value) ? resolved.value : [resolved.value];

        // Check each security group
        for (const sgId of sgIds) {
            const sg = resolver.getResource(sgId);

            if (sg?.Type === 'AWS::EC2::SecurityGroup' && this.sgAllowsUnrestrictedAccess(sg, resolver)) {
                return this.createScanResult(resource, stackName, `Security group ${sgId} allows 0.0.0.0/0`);
            }
        }

        return null;
    }

    private sgAllowsUnrestrictedAccess(sg: any, resolver: CloudFormationResolver): boolean {
        const properties = sg.Properties || {};

        // Check ingress rules
        const ingress = resolver.resolve(properties.SecurityGroupIngress);
        if (ingress.isResolved && Array.isArray(ingress.value)) {
            return ingress.value.some((rule: any) =>
                rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0'
            );
        }

        // Check separate ingress resources
        const ingressResources = resolver.getResourcesByType('AWS::EC2::SecurityGroupIngress');
        return ingressResources.some(resource => {
            const groupId = resolver.resolve(resource.Properties?.GroupId);
            const cidrIp = resolver.resolve(resource.Properties?.CidrIp);

            return (groupId.referencedResources.includes(sg.LogicalId) || groupId.value === sg.LogicalId) &&
                (cidrIp.value === '0.0.0.0/0');
        });
    }
}

export default new DocumentDB003Rule();