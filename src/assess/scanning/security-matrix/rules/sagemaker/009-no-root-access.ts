import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class SageMaker009Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-009',
            'HIGH',
            'SageMaker resource has root access enabled when not required',
            ['AWS::SageMaker::NotebookInstance']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        // Check if this rule applies to the resource type
        if (!this.appliesTo(resource.Type)) {
            return null;
        }

        // Handle missing Properties
        if (!resource.Properties) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Configure RootAccess property to 'Disabled'.`
            );
        }

        const rootAccess = resource.Properties.RootAccess;

        // If RootAccess is not specified, it defaults to 'Enabled'
        if (rootAccess === undefined || rootAccess === null) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add RootAccess property and set it to 'Disabled'. Use lifecycle configurations for software installation instead.`
            );
        }

        const resolver = new CloudFormationResolver(allResources);
        const resolvedValue = resolver.resolve<string>(rootAccess);

        if (resolvedValue.isResolved) {
            if (resolvedValue.value?.toLowerCase() === 'disabled') return null;

            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Set RootAccess property to 'Disabled'. Use lifecycle configurations for software installation instead.`
            );
        } else {
            // We couldn't resolve the value, so we need to flag it
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Set RootAccess property to an explicit string value ('Disabled') rather than using CloudFormation functions that cannot be validated at scan time.`
            );
        }
    }
}

export default new SageMaker009Rule();
