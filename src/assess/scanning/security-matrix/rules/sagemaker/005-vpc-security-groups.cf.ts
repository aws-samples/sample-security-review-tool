import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class SageMaker005Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-005',
            'HIGH',
            'SageMaker Studio should use VPC-only mode with discrete security groups per user profile',
            [
                'AWS::SageMaker::Domain',
                'AWS::SageMaker::UserProfile'
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

        if (resource.Type === 'AWS::SageMaker::UserProfile') {
            return this.evaluateUserProfile(resource, stackName, allResources);
        }

        return null;
    }

    private evaluateDomain(resource: CloudFormationResource, stackName: string): ScanResult | null {
        if (!resource.Properties) return null;

        const appNetworkAccessType = resource.Properties.AppNetworkAccessType;
        
        if (appNetworkAccessType !== 'VpcOnly') {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: SageMaker Domain is not configured for VPC-only mode`,
                `Set AppNetworkAccessType to 'VpcOnly' for enhanced security.`
            );
        }

        return null;
    }

    private evaluateUserProfile(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!resource.Properties || !allResources) return null;

        const userSettings = resource.Properties.UserSettings;
        if (!userSettings) return null;

        const securityGroups = userSettings.SecurityGroups;
        if (!securityGroups || !Array.isArray(securityGroups)) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}: UserProfile does not have dedicated security groups configured`,
                `Configure distinct security groups for each user profile.`
            );
        }

        const otherUserProfiles = allResources.filter(res => 
            res.Type === 'AWS::SageMaker::UserProfile' && 
            res.LogicalId !== resource.LogicalId
        );

        for (const otherProfile of otherUserProfiles) {
            if (!otherProfile.Properties?.UserSettings?.SecurityGroups) continue;
            
            const otherSecurityGroups = otherProfile.Properties.UserSettings.SecurityGroups;
            const hasSharedSecurityGroup = securityGroups.some((sg: any) => 
                otherSecurityGroups.includes(sg)
            );

            if (hasSharedSecurityGroup) {
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}: UserProfile shares security groups with other user profiles`,
                    `Use distinct security groups for each user profile.`
                );
            }
        }

        return null;
    }
}

export default new SageMaker005Rule();