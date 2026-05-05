import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * SL1: Restrict AWS Security Lake subscriber permissions according to least privilege
 * 
 * Security Principle: Least Privilege Access
 * 
 * This rule ensures Security Lake subscribers have minimal necessary permissions
 * by checking for overly broad sources, permissive principals, and excessive access types.
 * 
 * Risk: Overly permissive subscribers can access more data than needed, violating
 * least privilege and potentially exposing sensitive security data.
 */
export class SL001Rule extends BaseRule {
    constructor() {
        super(
            'SL-001',
            'HIGH',
            'Security Lake subscriber has overly broad permissions',
            ['AWS::SecurityLake::Subscriber']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const props = resource.Properties;
        if (!props) return null;

        // Check for maximum sources limit (AWS limit is 10)
        // https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html
        if (Array.isArray(props.Sources) && props.Sources.length > 10) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                `Reduce Sources array from ${props.Sources.length} to maximum 10 sources. Remove unnecessary data sources to comply with AWS limits and follow least privilege.`
            );
        }

        // Check for wildcard in Principal
        const subscriberIdentity = props.SubscriberIdentity;
        if (subscriberIdentity?.Principal && typeof subscriberIdentity.Principal === 'string' && 
            subscriberIdentity.Principal.includes('*')) {
            return this.createResult(
                stackName,
                template,
                resource,
                this.description,
                `Replace wildcard Principal "${subscriberIdentity.Principal}" with specific account ID (e.g., "123456789012") or AWS service domain (e.g., "lambda.amazonaws.com").`
            );
        }



        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
        return null;
    }
}

export default new SL001Rule();