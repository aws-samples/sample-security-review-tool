import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SQS-008: Use VPC endpoints when resources cannot reach SQS API endpoints over internet routes
 * 
 * Security Principle: Defense in Depth
 * 
 * This rule ensures that SQS queue policies enforce VPC endpoint usage when private
 * network connectivity is required, preventing access over public internet.
 * 
 * Risk: Without VPC endpoint enforcement, SQS traffic may traverse public internet
 * even when private connectivity is intended.
 */
export class Sqs008Rule extends BaseRule {
    constructor() {
        super(
            'SQS-008',
            'HIGH',
            'Consider adding VPC endpoint enforcement if this workload requires private network connectivity to SQS',
            ['AWS::SQS::QueuePolicy']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;
        
        const policyDocument = resource.Properties?.PolicyDocument;
        if (!policyDocument?.Statement) return null;

        const statements = Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
        
        // Check if policy has any VPC conditions (indicates private connectivity intent)
        const hasVpcConditions = statements.some((stmt: any) => this.hasVpcEndpointCondition(stmt.Condition));
        
        // Only enforce if policy already shows VPC intent
        if (!hasVpcConditions) return null;
        
        // Check if there's a Deny statement enforcing VPC endpoint
        const hasDenyVpcEnforcement = statements.some((stmt: any) => 
            stmt.Effect === 'Deny' && this.hasVpcEndpointCondition(stmt.Condition)
        );

        if (!hasDenyVpcEnforcement) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Add Deny statement with Condition: { "StringNotEquals": { "aws:sourceVpce": "vpce-ENDPOINT_ID" } } to enforce VPC endpoint usage'
            );
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private hasVpcEndpointCondition(conditions: any): boolean {
        if (!conditions) return false;

        // Check for VPC endpoint conditions
        const vpcEndpointKeys = [
            'aws:sourceVpce',
            'aws:SourceVpce',
            'aws:sourceVpc', 
            'aws:SourceVpc'
        ];

        for (const operator of Object.keys(conditions)) {
            const operatorConditions = conditions[operator];
            
            for (const conditionKey of vpcEndpointKeys) {
                if (operatorConditions[conditionKey]) {
                    return true;
                }
            }
        }

        return false;
    }
}

export default new Sqs008Rule();