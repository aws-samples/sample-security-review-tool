import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class Lex001Rule extends BaseRule {
    constructor() {
        super(
            'LEX-001',
            'HIGH',
            'Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance',
            ['AWS::Lex::Bot']
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) return null;

        const resolver = new CloudFormationResolver(allResources);
        const childDirected = resolver.resolve<boolean>(resource.Properties?.DataPrivacy?.ChildDirected);

        if (childDirected.isResolved && childDirected.value === true) return null;

        if (childDirected.isIntrinsicFunction) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Set DataPrivacy.ChildDirected property to an explicit boolean value ('true') rather than using CloudFormation functions that cannot be validated at scan time.`
            );
        }

        return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set DataPrivacy.ChildDirected property to 'true' to comply with COPPA.`
        );
    }
}

export default new Lex001Rule();