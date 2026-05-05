import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class SageMaker008Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-008',
            'HIGH',
            'SageMaker resource allows unrestricted data access without proper network controls',
            [
                'AWS::SageMaker::Domain',
                'AWS::SageMaker::NotebookInstance'
            ]
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) {
            return null;
        }

        if (resource.Type === 'AWS::SageMaker::Domain') {
            return this.evaluateDomain(resource, stackName);
        }

        if (resource.Type === 'AWS::SageMaker::NotebookInstance') {
            return this.evaluateNotebookInstance(resource, stackName);
        }

        return null;
    }

    private evaluateDomain(resource: CloudFormationResource, stackName: string): ScanResult | null {
        if (!resource.Properties) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Configure Domain with VpcId, SubnetIds, and AppNetworkAccessType set to 'VpcOnly' to restrict data access.`
            );
        }

        const vpcId = resource.Properties.VpcId;
        const subnetIds = resource.Properties.SubnetIds;
        const appNetworkAccessType = resource.Properties.AppNetworkAccessType;

        // Check for VPC configuration
        if (!vpcId || !subnetIds) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: Domain is not configured with VPC network isolation`,
                `Add VpcId and SubnetIds properties to restrict data access to VPC-only mode.`
            );
        }

        // Check for VPC-only mode
        if (appNetworkAccessType !== 'VpcOnly') {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: Domain allows public internet access`,
                `Set AppNetworkAccessType to 'VpcOnly' to restrict data access and prevent internet connectivity.`
            );
        }

        return null;
    }

    private evaluateNotebookInstance(resource: CloudFormationResource, stackName: string): ScanResult | null {
        if (!resource.Properties) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Configure NotebookInstance with SubnetId and DirectInternetAccess set to 'Disabled' to restrict data access.`
            );
        }

        const subnetId = resource.Properties.SubnetId;
        const directInternetAccess = resource.Properties.DirectInternetAccess;

        // Check for VPC configuration
        if (!subnetId) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: NotebookInstance is not configured with VPC network isolation`,
                `Add SubnetId property to place the notebook instance in a VPC for controlled data access.`
            );
        }

        // Check for internet access restriction
        if (directInternetAccess !== 'Disabled') {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: NotebookInstance allows direct internet access`,
                `Set DirectInternetAccess to 'Disabled' to restrict data access and implement controlled egress.`
            );
        }

        return null;
    }
}

export default new SageMaker008Rule();