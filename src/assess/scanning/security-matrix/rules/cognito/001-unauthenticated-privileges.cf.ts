import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class Cognito001Rule extends BaseRule {
    constructor() {
        super(
            'COGNITO-001',
            'HIGH',
            'Cognito Identity Pool allows unauthenticated users',
            ['AWS::Cognito::IdentityPool']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const resolver = new CloudFormationResolver(allResources);
        const allowUnauthenticated = resolver.resolve<boolean>(resource.Properties?.AllowUnauthenticatedIdentities);

        // If unauthenticated identities are not allowed, the rule passes
        if (allowUnauthenticated.isResolved && allowUnauthenticated.value === false) return null;

        // If we can't resolve the value or it's true, flag it
        return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set AllowUnauthenticatedIdentities to 'false' to prevent unauthenticated access.`
        );
    }
}

export default new Cognito001Rule();
