import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

export class Evb004Rule extends BaseRule {
    constructor() {
        super(
            'EVB-004',
            'HIGH',
            'EventBridge archive does not have a finite retention period configured. Events should not be kept in the archive for longer than necessary',
            ['AWS::Events::Archive']
        );
    }

    public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null | undefined {
        if (!this.appliesTo(resource.Type)) return null;

        const retentionDays = resource.Properties?.RetentionDays;

        // Check if RetentionDays is missing or set to 0 (infinite retention)
        if (!retentionDays) {
            return this.createResult(
                stackName,
                template,
                resource,
                `${this.description}`,
                'Set RetentionDays property to 30'
            );
        }
        return null;
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        return null;
    }
}

export default new Evb004Rule();
