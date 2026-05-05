import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class SageMaker010Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-010',
            'MEDIUM',
            'SageMaker role is shared across multiple features violating least-privilege',
            [
                'AWS::SageMaker::Domain',
                'AWS::SageMaker::UserProfile',
                'AWS::SageMaker::NotebookInstance',
                'AWS::SageMaker::Model',
                'AWS::SageMaker::Pipeline',
                'AWS::SageMaker::Endpoint',
                'AWS::SageMaker::EndpointConfig'
            ]
        );
    }

    public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
        if (!this.appliesTo(resource.Type) || !allResources) {
            return null;
        }

        const currentRole = this.getRoleFromResource(resource);
        if (!currentRole) return null;

        const resourcesUsingRole = this.findResourcesUsingRole(currentRole, allResources);
        const resourceTypeMap = new Map<string, CloudFormationResource[]>();
        
        for (const res of resourcesUsingRole) {
            if (!resourceTypeMap.has(res.Type)) {
                resourceTypeMap.set(res.Type, []);
            }
            resourceTypeMap.get(res.Type)?.push(res);
        }

        if (resourceTypeMap.size > 1 && resourcesUsingRole[0].LogicalId === resource.LogicalId) {
            const resourceTypes = Array.from(resourceTypeMap.keys()).join(', ');
            const violatingResources = resourcesUsingRole.map(r => r.LogicalId).join(', ');
            const fixInstructions = this.generateFixInstructions(resourcesUsingRole, currentRole);
            
            return this.createScanResult(
                resource,
                stackName,
                `Role '${currentRole}' is shared across multiple SageMaker features: ${resourceTypes}. Violating resources: ${violatingResources}`,
                fixInstructions
            );
        }

        return null;
    }

    private getRoleFromResource(resource: CloudFormationResource): string | null {
        if (!resource.Properties) return null;

        let roleProperty: any = null;
        switch (resource.Type) {
            case 'AWS::SageMaker::Domain':
                roleProperty = resource.Properties.DefaultUserSettings?.ExecutionRole;
                break;
            case 'AWS::SageMaker::UserProfile':
                roleProperty = resource.Properties.UserSettings?.ExecutionRole;
                break;
            case 'AWS::SageMaker::NotebookInstance':
                roleProperty = resource.Properties.RoleArn;
                break;
            case 'AWS::SageMaker::Model':
            case 'AWS::SageMaker::Pipeline':
                roleProperty = resource.Properties.ExecutionRoleArn;
                break;
            case 'AWS::SageMaker::Endpoint':
            case 'AWS::SageMaker::EndpointConfig':
                roleProperty = resource.Properties.ExecutionRoleArn;
                break;
            default:
                return null;
        }

        if (!roleProperty) return null;

        if (typeof roleProperty === 'object' && roleProperty !== null) {
            if (roleProperty.Ref) return roleProperty.Ref;
            if (roleProperty['Fn::GetAtt']) {
                const [resourceId] = Array.isArray(roleProperty['Fn::GetAtt'])
                    ? roleProperty['Fn::GetAtt']
                    : [roleProperty['Fn::GetAtt']];
                return resourceId;
            }
        }

        return typeof roleProperty === 'string' ? roleProperty : null;
    }

    private findResourcesUsingRole(role: string, resources: CloudFormationResource[]): CloudFormationResource[] {
        return resources.filter(res => {
            if (!this.appliesTo(res.Type)) return false;
            const resourceRole = this.getRoleFromResource(res);
            return resourceRole === role;
        });
    }

    private generateFixInstructions(resources: CloudFormationResource[], sharedRole: string): string {
        let instructions = '';
        
        for (const resource of resources) {
            const resourceTypeFull = resource.Type.split('::').pop() || '';
            // Simplify resource type for role naming - this matches test expectations
            let resourceType = resourceTypeFull;
            if (resourceTypeFull === 'NotebookInstance') {
                resourceType = 'Notebook';
            }
            
            const newRoleName = `${resource.LogicalId}${resourceType}Role`;
            
            instructions += `Create IAM role '${newRoleName}' with appropriate permissions for ${resourceTypeFull}.\n`;
            
            switch (resource.Type) {
                case 'AWS::SageMaker::Domain':
                    instructions += `Update ${resource.LogicalId}.Properties.DefaultUserSettings.ExecutionRole to use the new role.\n`;
                    break;
                case 'AWS::SageMaker::UserProfile':
                    instructions += `Update ${resource.LogicalId}.Properties.UserSettings.ExecutionRole to use the new role.\n`;
                    break;
                case 'AWS::SageMaker::NotebookInstance':
                    instructions += `Update ${resource.LogicalId}.Properties.RoleArn to use the new role.\n`;
                    break;
                case 'AWS::SageMaker::Model':
                case 'AWS::SageMaker::Pipeline':
                    instructions += `Update ${resource.LogicalId}.Properties.ExecutionRoleArn to use the new role.\n`;
                    break;
                default:
                    instructions += `Update ${resource.LogicalId} to use the new role.\n`;
            }
        }
        
        instructions += 'Use AWS SageMaker Role Manager for domains.';
        
        return instructions;
    }
}

export default new SageMaker010Rule();
