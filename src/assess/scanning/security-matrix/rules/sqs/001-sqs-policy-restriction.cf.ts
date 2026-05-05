import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SQS-001: Restrict SQS policies to known IAM Principals/AWS Accounts when cross-account access is required
 * 
 * Security Principle: Principle of Least Privilege
 * 
 * This rule ensures that SQS queue policies follow secure cross-account access patterns:
 * 1. Prefer specific IAM Principals/AWS Account IDs over wildcards
 * 2. If wildcards are necessary, require restrictive IAM Conditions to scope access
 * 3. Prevent unrestricted cross-account access that could lead to data exfiltration or unauthorized queue access
 * 
 * Risk: Without proper restrictions, malicious actors from any AWS account could:
 * - Send messages to your SQS queue
 * - Receive messages from your SQS queue
 * - Potentially access sensitive data or disrupt service operations
 */
export class Sqs001Rule extends BaseRule {
    constructor() {
        super(
            'SQS-001',
            'HIGH',
            'SQS policy allows wildcard principals without restrictive conditions, violating principle of least privilege',
            ['AWS::SQS::QueuePolicy']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;
        
        const policyDocument = resource.Properties?.PolicyDocument;
        if (!policyDocument?.Statement) return null;

        const statements = Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
        
        for (const stmt of statements) {
            if (this.isCrossAccountStatement(stmt) && this.hasWildcardPrincipal(stmt) && !this.hasSecurityConditions(stmt.Condition)) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    'Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } } (replace ACCOUNT_ID with actual AWS account)'
                );
            }
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private isCrossAccountStatement(statement: any): boolean {
        if (!statement?.Principal) return false;

        // Check for AWS service principals or wildcard principals
        if (statement.Principal.Service || statement.Principal === '*' || statement.Principal.AWS === '*') {
            return true;
        }

        // Check for cross-account principals (different account IDs)
        if (statement.Principal.AWS) {
            const principals = Array.isArray(statement.Principal.AWS) ? statement.Principal.AWS : [statement.Principal.AWS];
            
            for (const principal of principals) {
                if (typeof principal === 'string') {
                    // Check for wildcards, full ARNs, or bare account IDs
                    if (principal.includes('*') || 
                        principal.match(/arn:aws:iam::\d{12}:/) || 
                        principal.match(/^\d{12}$/)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private hasWildcardPrincipal(statement: any): boolean {
        if (!statement?.Principal) return false;
        
        // Check for wildcard principals
        if (statement.Principal === '*' || statement.Principal.AWS === '*') {
            return true;
        }

        // Check for wildcard in AWS principals array
        if (statement.Principal.AWS) {
            const principals = Array.isArray(statement.Principal.AWS) ? statement.Principal.AWS : [statement.Principal.AWS];
            return principals.some((p: string) => typeof p === 'string' && p.includes('*'));
        }

        return false;
    }

    private hasSecurityConditions(conditions: any): boolean {
        if (!conditions) return false;

        const restrictiveConditionKeys = [
            'aws:SourceArn',
            'aws:SourceAccount',
            'aws:PrincipalAccount',
            'aws:PrincipalOrgID',
            'aws:PrincipalOrgPaths'
        ];

        // Check all condition operators (StringEquals, StringLike, etc.)
        for (const operator of Object.keys(conditions)) {
            const operatorConditions = conditions[operator];
            
            for (const conditionKey of restrictiveConditionKeys) {
                if (operatorConditions[conditionKey]) {
                    return true;
                }
            }
        }

        return false;
    }


}

export default new Sqs001Rule();