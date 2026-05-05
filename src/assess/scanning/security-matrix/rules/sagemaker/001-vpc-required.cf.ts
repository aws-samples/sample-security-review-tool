import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class SageMaker001Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-001',
            'HIGH',
            'SageMaker resource is not configured to use a VPC',
            ['AWS::SageMaker::NotebookInstance', 'AWS::SageMaker::Domain']
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
                `Configure the resource to use a VPC for improved security.`
            );
        }

        if (resource.Type === 'AWS::SageMaker::NotebookInstance') {
            return this.evaluateNotebookInstance(resource, stackName);
        }

        if (resource.Type === 'AWS::SageMaker::Domain') {
            return this.evaluateDomain(resource, stackName);
        }

        return null;
    }

    private evaluateNotebookInstance(resource: CloudFormationResource, stackName: string): ScanResult | null {
        const subnetId = resource.Properties.SubnetId;

        // If SubnetId is not specified, the notebook instance is not in a VPC
        if (subnetId === undefined || subnetId === null) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add SubnetId property to provision the notebook instance in a VPC subnet.`
            );
        }

        return null;
    }

    private evaluateDomain(resource: CloudFormationResource, stackName: string): ScanResult | null {
        const vpcId = resource.Properties.VpcId;
        const subnetIds = resource.Properties.SubnetIds;

        // If VpcId is not specified, the domain is not in a VPC
        if (vpcId === undefined || vpcId === null) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add VpcId property to provision the domain in a VPC.`
            );
        }

        // Check if SubnetIds is missing when VpcId is present
        if (subnetIds === undefined || subnetIds === null) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add SubnetIds property along with VpcId to properly configure VPC networking.`
            );
        }

        return null;
    }
}

export default new SageMaker001Rule();
