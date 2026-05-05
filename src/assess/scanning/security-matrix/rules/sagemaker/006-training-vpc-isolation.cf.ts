import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class SageMaker006Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-006',
            'HIGH',
            'SageMaker training or processing job lacks VPC network isolation for data protection',
            [
                'AWS::SageMaker::TrainingJob',
                'AWS::SageMaker::ProcessingJob',
                'AWS::SageMaker::TransformJob'
            ]
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type)) {
            return null;
        }

        if (!resource.Properties) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Configure VpcConfig with SecurityGroupIds and Subnets to enable network isolation for training/processing containers.`
            );
        }

        const vpcConfig = resource.Properties.VpcConfig;
        const networkConfig = resource.Properties.NetworkConfig;

        // Check for VPC configuration
        if (!vpcConfig && !networkConfig) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add VpcConfig with SecurityGroupIds and Subnets to implement network isolation and prevent unauthorized data access.`
            );
        }

        // Validate VpcConfig structure
        if (vpcConfig) {
            const securityGroupIds = vpcConfig.SecurityGroupIds;
            const subnets = vpcConfig.Subnets;

            if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}`,
                    `Add SecurityGroupIds array to VpcConfig to control network access for training/processing containers.`
                );
            }

            if (!subnets || !Array.isArray(subnets) || subnets.length === 0) {
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}`,
                    `Add Subnets array to VpcConfig to place training/processing containers in isolated network.`
                );
            }
        }

        // Validate NetworkConfig for ProcessingJob
        if (networkConfig && resource.Type === 'AWS::SageMaker::ProcessingJob') {
            const enableNetworkIsolation = networkConfig.EnableNetworkIsolation;
            
            if (enableNetworkIsolation !== true) {
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}`,
                    `Set NetworkConfig.EnableNetworkIsolation to true to prevent internet access from processing containers.`
                );
            }
        }

        return null;
    }
}

export default new SageMaker006Rule();