import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';
/**
 * DOCDB-003: Ensures DocumentDB cluster security groups do not allow
 * unrestricted ingress from `0.0.0.0/0` or `::/0`.
 *
 * Uses template-aware evaluation to trace each security group ID listed
 * in `VpcSecurityGroupIds` back to its `AWS::EC2::SecurityGroup` resource,
 * then inspects both inline `SecurityGroupIngress` entries and standalone
 * `AWS::EC2::SecurityGroupIngress` resources for open-CIDR rules that
 * reach the cluster's TCP port. Each ingress-rule field is individually
 * resolved through `CloudFormationResolver` to prevent unresolved
 * intrinsics from producing false positives during protocol and port
 * classification.
 *
 * Checks:
 *  - Resolves `VpcSecurityGroupIds` to in-template `AWS::EC2::SecurityGroup`
 *    resources and inspects their ingress rules.
 *  - Detects inline `SecurityGroupIngress` rules whose `CidrIp` is
 *    `0.0.0.0/0` or `CidrIpv6` is `::/0` and whose protocol and port
 *    range cover the DocumentDB port (default 27017, or the resolved
 *    `Port` property of the cluster).
 *  - Detects standalone `AWS::EC2::SecurityGroupIngress` resources
 *    targeting the same SG (matched by `GroupId`, logical-ID reference,
 *    or matching resolved `GroupName`) with the same open-CIDR criteria.
 *  - Treats `IpProtocol` `-1` or any non-TCP/UDP/ICMP/ICMPv6 value as
 *    allowing all ports regardless of the declared port range.
 *  - Recognises TCP by both name (`tcp`) and protocol number (`6`);
 *    non-TCP protocols (UDP, ICMP, ICMPv6) cannot expose a TCP service
 *    and are excluded from port-range evaluation.
 *
 * Resolves CloudFormation references using `CloudFormationResolver` for
 * `VpcSecurityGroupIds`, the cluster `Port`, and every individual field
 * of each ingress rule (`IpProtocol`, `CidrIp`, `CidrIpv6`, `FromPort`,
 * `ToPort`). Unresolvable values at any of these levels cause the rule to
 * abstain rather than emit a false positive or false negative.
 *
 * Known limitations:
 *  - Cannot detect exposure through a manually modified default VPC
 *    security group when `VpcSecurityGroupIds` is omitted; the default SG
 *    is not declared in the template and is therefore invisible to
 *    single-template scanning.
 *  - Cannot inspect security groups referenced by literal `sg-*` strings,
 *    `Fn::ImportValue`, cross-stack references, or `Ref` to parameters;
 *    the rule correctly abstains in these cases but real exposure via
 *    such groups is undetectable.
 *  - Inline `SecurityGroupIngress` arrays whose entire value is an
 *    unresolvable intrinsic (e.g., a parameter producing the whole list)
 *    cause the inline check to be skipped; standalone
 *    `AWS::EC2::SecurityGroupIngress` resources are still evaluated.
 *
 * @evaluated 2026-05-05
 */
export class DocumentDB003Rule extends BaseRule {
    private static readonly DEFAULT_DOCDB_PORT = 27017;
    private static readonly PORT_AWARE_PROTOCOLS = ['tcp', 'udp', 'icmp', 'icmpv6'];
    private static readonly TCP_PROTOCOL_VALUES = ['tcp', '6'];

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

        // When VpcSecurityGroupIds is omitted, the cluster uses the default VPC security
        // group, which only allows ingress from resources in the same security group -
        // not from 0.0.0.0/0. Therefore this rule does not apply.
        // See: https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html
        if (!vpcSecurityGroupIds) {
            return null;
        }

        const resolved = resolver.resolve(vpcSecurityGroupIds, {
            treatLiteralStringsAs: 'external-references'
        });

        // When the security group references cannot be resolved statically (e.g. Ref to
        // a parameter, Fn::ImportValue, or external sg-id), the scanner cannot inspect
        // the underlying ingress rules. Returning a finding here would be a false
        // positive, so we abstain.
        if (!resolved.isResolved) {
            return null;
        }

        const sgIds = Array.isArray(resolved.value) ? resolved.value : [resolved.value];
        const clusterPort = this.getClusterPort(resource, resolver);

        // If the Port property is specified but cannot be resolved (e.g. Ref to a
        // parameter, Fn::If, Fn::ImportValue), we cannot determine which port the
        // cluster will actually listen on at deploy time, so we cannot reliably
        // decide whether the security group exposes the DocumentDB port. Abstain.
        if (clusterPort === null) {
            return null;
        }

        // Each entry in VpcSecurityGroupIds independently controls ingress, so any
        // single open SG exposes the cluster. We must therefore evaluate every
        // resolvable, in-template SG for definite violations before abstaining on
        // unresolvable entries - otherwise a violation on a resolvable sibling would
        // be silently masked by an earlier external/parameterized SG id.
        let hasUnresolvableSg = false;
        for (const sgId of sgIds) {
            const sg = resolver.getResource(sgId);

            // If the id does not map to a SecurityGroup resource defined in this
            // template (either missing entirely or of a different type), we cannot
            // inspect its ingress rules. Record that we encountered an
            // uninspectable entry and continue checking remaining SGs.
            if (!sg || sg.Type !== 'AWS::EC2::SecurityGroup') {
                hasUnresolvableSg = true;
                continue;
            }

            if (this.sgAllowsUnrestrictedAccess(sg, resolver, clusterPort)) {
                return this.createScanResult(resource, stackName, `Security group ${sgId} allows 0.0.0.0/0 to DocumentDB port ${clusterPort}`);
            }
        }

        // No definite violation found. If any SG was uninspectable, abstain rather
        // than asserting the cluster is safe.
        if (hasUnresolvableSg) {
            return null;
        }

        return null;
    }

    private getClusterPort(resource: CloudFormationResource, resolver: CloudFormationResolver): number | null {
        // When Port is omitted entirely, DocumentDB uses the engine default (27017).
        if (resource.Properties?.Port === undefined) {
            return DocumentDB003Rule.DEFAULT_DOCDB_PORT;
        }

        const port = resolver.resolve(resource.Properties.Port);
        if (port.isResolved && typeof port.value === 'number') {
            return port.value;
        }
        if (port.isResolved && typeof port.value === 'string' && /^\d+$/.test(port.value)) {
            return parseInt(port.value, 10);
        }
        // Port is specified but cannot be resolved statically - signal abstention.
        return null;
    }

    private sgAllowsUnrestrictedAccess(sg: any, resolver: CloudFormationResolver, clusterPort: number): boolean {
        const properties = sg.Properties || {};

        // Check inline ingress rules
        const ingress = resolver.resolve(properties.SecurityGroupIngress);
        if (ingress.isResolved && Array.isArray(ingress.value)) {
            const inlineRules = ingress.value.map((rule: any) => this.normalizeIngressRule(rule, resolver));
            if (inlineRules.some(rule => this.ruleExposesPortToCidr(rule, clusterPort))) {
                return true;
            }
        }

        // Check separate ingress resources
        const ingressResources = resolver.getResourcesByType('AWS::EC2::SecurityGroupIngress');
        return ingressResources.some(ingressResource => {
            if (!this.ingressTargetsSecurityGroup(ingressResource, sg, resolver)) return false;
            return this.ruleExposesPortToCidr(this.normalizeIngressRule(ingressResource.Properties, resolver), clusterPort);
        });
    }

    // Resolves each individual ingress-rule field through the resolver so that
    // unresolvable intrinsic objects (e.g. {Ref: 'SomeParam'}, {Fn::If: [...]})
    // become `undefined` rather than being passed downstream as opaque objects.
    // This is critical for inline SecurityGroupIngress entries: resolver.resolve
    // on the array as a whole may surface entries whose nested fields are still
    // unresolved intrinsics, which would otherwise cause protocolAllowsAllPorts
    // to mis-classify {Ref:'...'} as a non-port-aware protocol and produce a
    // false positive when CidrIp is literally '0.0.0.0/0'.
    private normalizeIngressRule(rule: any, resolver: CloudFormationResolver): any {
        const properties = rule || {};
        return {
            IpProtocol: resolver.resolve(properties.IpProtocol).value,
            CidrIp: resolver.resolve(properties.CidrIp).value,
            CidrIpv6: resolver.resolve(properties.CidrIpv6).value,
            FromPort: resolver.resolve(properties.FromPort).value,
            ToPort: resolver.resolve(properties.ToPort).value
        };
    }

    // A standalone AWS::EC2::SecurityGroupIngress resource may reference its target
    // security group either by GroupId (any VPC) or by GroupName (default VPC only).
    // We must consider both to avoid false negatives on default-VPC templates.
    // See: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupingress.html
    private ingressTargetsSecurityGroup(ingressResource: CloudFormationResource, sg: any, resolver: CloudFormationResolver): boolean {
        const groupId = resolver.resolve(ingressResource.Properties?.GroupId);
        if (groupId.referencedResources.includes(sg.LogicalId) || groupId.value === sg.LogicalId) {
            return true;
        }

        const ingressGroupName = resolver.resolve(ingressResource.Properties?.GroupName);
        if (ingressGroupName.referencedResources.includes(sg.LogicalId)) {
            return true;
        }

        const sgGroupName = resolver.resolve(sg.Properties?.GroupName);
        if (sgGroupName.isResolved && ingressGroupName.isResolved &&
            sgGroupName.value !== undefined && sgGroupName.value === ingressGroupName.value) {
            return true;
        }

        return false;
    }

    private ruleExposesPortToCidr(rule: any, clusterPort: number): boolean {
        if (!this.isOpenCidr(rule)) return false;
        // Per AWS docs, IpProtocol '-1' or any protocol other than tcp/udp/icmp/icmpv6
        // allows traffic on all ports regardless of any port range specified.
        if (this.protocolAllowsAllPorts(rule.IpProtocol)) return true;
        // DocumentDB listens on TCP only. UDP/ICMP/ICMPv6 rules - even ones whose
        // FromPort/ToPort overlap the cluster port - cannot expose the TCP service
        // (for ICMP/ICMPv6 those fields denote type/code, not ports at all).
        if (!this.isTcpProtocol(rule.IpProtocol)) return false;
        return this.portRangeIncludes(rule.FromPort, rule.ToPort, clusterPort);
    }

    private isOpenCidr(rule: any): boolean {
        return rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0';
    }

    // IpProtocol of '-1' or any protocol number/name other than tcp/udp/icmp/icmpv6
    // bypasses the port range entirely. An absent IpProtocol is treated as port-aware
    // so the existing port-range logic applies.
    private protocolAllowsAllPorts(ipProtocol: any): boolean {
        if (ipProtocol === undefined || ipProtocol === null) return false;
        const normalized = String(ipProtocol).toLowerCase();
        return !DocumentDB003Rule.PORT_AWARE_PROTOCOLS.includes(normalized);
    }

    // DocumentDB is a TCP-only service, so only TCP rules ('tcp' or protocol number 6)
    // can expose its port. An absent/unresolvable IpProtocol is not treated as TCP to
    // avoid false positives on UDP/ICMP rules whose protocol could not be inspected.
    private isTcpProtocol(ipProtocol: any): boolean {
        if (ipProtocol === undefined || ipProtocol === null) return false;
        const normalized = String(ipProtocol).toLowerCase();
        return DocumentDB003Rule.TCP_PROTOCOL_VALUES.includes(normalized);
    }

    // Determines whether a TCP rule's port range includes the cluster port. This
    // method is only invoked for TCP rules (callers gate on isTcpProtocol), and per
    // AWS docs TCP rules must specify a port range - CloudFormation rejects TCP
    // ingress without FromPort/ToPort at deploy time. We therefore do NOT treat
    // missing FromPort/ToPort as "all ports" here; doing so would produce false
    // positives on rules that omit ports (e.g. ICMP rules misclassified upstream,
    // or otherwise invalid templates). All-ports semantics for non-TCP/UDP/ICMP
    // protocols are handled separately by protocolAllowsAllPorts.
    private portRangeIncludes(fromPort: any, toPort: any, clusterPort: number): boolean {
        const from = this.coercePort(fromPort);
        const to = this.coercePort(toPort);

        if (from === null && to === null) return false;
        if (from !== null && to !== null) return clusterPort >= from && clusterPort <= to;
        if (from !== null) return clusterPort >= from;
        return clusterPort <= (to as number);
    }

    private coercePort(value: any): number | null {
        if (typeof value === 'number') return value;
        if (typeof value === 'string' && /^-?\d+$/.test(value)) return parseInt(value, 10);
        return null;
    }
}

export default new DocumentDB003Rule();
