import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SQS-007: Separate SQS queue administration permissions from SQS queue usage permissions
 * 
 * Security Principle: Principle of Least Privilege
 * 
 * This rule ensures that IAM principals with administrative permissions (create, update, delete)
 * are separated from those with usage permissions (send, receive messages).
 * 
 * Risk: Combining admin and usage permissions violates least privilege and increases blast radius
 * if credentials are compromised.
 */
export class Sqs007Rule extends BaseRule {
    constructor() {
        super(
            'SQS-007',
            'HIGH',
            'SQS policy grants both administrative and usage permissions to the same principal, violating principle of least privilege',
            ['AWS::SQS::QueuePolicy']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;
        
        const policyDocument = resource.Properties?.PolicyDocument;
        if (!policyDocument?.Statement) return null;

        const statements = Array.isArray(policyDocument.Statement) ? policyDocument.Statement : [policyDocument.Statement];
        
        for (const stmt of statements) {
            const violatingActions = this.getViolatingActions(stmt.Action);
            if (violatingActions) {
                return this.createResult(
                    stackName,
                    template,
                    resource,
                    this.description,
                    `Separate admin actions [${violatingActions.admin.join(', ')}] from usage actions [${violatingActions.usage.join(', ')}] into different statements`
                );
            }
        }

        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }

    private getViolatingActions(actions: any): { admin: string[], usage: string[] } | null {
        if (!actions) return null;

        const actionList = Array.isArray(actions) ? actions : [actions];
        
        const adminActions = [
            'sqs:CreateQueue',
            'sqs:DeleteQueue',
            'sqs:SetQueueAttributes',
            'sqs:GetQueueAttributes',
            'sqs:ListQueues',
            'sqs:ListQueueTags',
            'sqs:ListDeadLetterSourceQueues',
            'sqs:TagQueue',
            'sqs:UntagQueue',
            'sqs:AddPermission',
            'sqs:RemovePermission',
            'sqs:PurgeQueue'
        ];

        const usageActions = [
            'sqs:SendMessage',
            'sqs:SendMessageBatch',
            'sqs:ReceiveMessage',
            'sqs:DeleteMessage',
            'sqs:DeleteMessageBatch',
            'sqs:ChangeMessageVisibility',
            'sqs:ChangeMessageVisibilityBatch',
            'sqs:GetQueueUrl'
        ];

        const foundAdmin = actionList.filter((action: string) => 
            adminActions.includes(action) || action === 'sqs:*'
        );

        const foundUsage = actionList.filter((action: string) => 
            usageActions.includes(action) || action === 'sqs:*'
        );

        if (foundAdmin.length > 0 && foundUsage.length > 0) {
            return {
                admin: foundAdmin,
                usage: foundUsage
            };
        }

        return null;
    }
}

export default new Sqs007Rule();