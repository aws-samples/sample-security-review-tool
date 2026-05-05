import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class SageMaker003Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-003',
            'HIGH',
            'SageMaker resource has direct internet access enabled without proper authentication strategy',
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
                `Configure DirectInternetAccess property to 'Disabled'.`
            );
        }

        const directInternetAccess = resource.Properties.DirectInternetAccess;

        // If DirectInternetAccess is not specified, it defaults to 'Enabled'
        if (directInternetAccess === undefined || directInternetAccess === null) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add DirectInternetAccess property and set it to 'Disabled'. Implement federated authentication for users.`
            );
        }

        const resolver = new CloudFormationResolver(allResources);
        const resolvedValue = resolver.resolve<string>(directInternetAccess);

        if (resolvedValue.isResolved) {
            if (resolvedValue.value === 'Disabled') return null;

            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Set DirectInternetAccess property to 'Disabled'. Use federated authentication and well-defined access control strategy.`
            );
        } else {
            // We couldn't resolve the value, so we need to flag it
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Set DirectInternetAccess property to an explicit string value ('Disabled') rather than using CloudFormation functions that cannot be validated at scan time.`
            );
        }
    }
}

export default new SageMaker003Rule();
