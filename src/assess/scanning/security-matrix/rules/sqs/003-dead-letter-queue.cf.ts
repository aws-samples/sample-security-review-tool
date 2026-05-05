import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SQS-003: Implement a dead-letter queue to isolate messages that cannot be processed by non-Lambda queue consumers
 * 
 * This rule flags SQS queues without dead-letter queues configured.
 * Note: Cannot detect Lambda consumers in other templates - manual verification may be needed.
 * Dead-letter queues prevent backlog of unprocessed messages and improve system reliability.
 */
export class Sqs003Rule extends BaseRule {
    constructor() {
        super(
            'SQS-003',
            'HIGH',
            'SQS queue does not have a dead-letter queue configured to handle unprocessable messages',
            ['AWS::SQS::Queue']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;
        
        const redrivePolicy = resource.Properties?.RedrivePolicy;
        
        // Check if RedrivePolicy is missing (no dead-letter queue configured)
        // Note: This rule cannot detect Lambda consumers in other templates
        if (!redrivePolicy) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                'Add RedrivePolicy to Properties with deadLetterTargetArn: "arn:aws:sqs:region:account:dlq-name" and maxReceiveCount: 3'
            );
        }

        return null;
    }



    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}

export default new Sqs003Rule();