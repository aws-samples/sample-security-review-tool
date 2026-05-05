import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

export class SageMaker004Rule extends BaseRule {
    constructor() {
        super(
            'SAGEMAKER-004',
            'HIGH',
            'SageMaker Domain is configured to use Studio Classic instead of the new Studio experience',
            ['AWS::SageMaker::Domain']
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
                `Configure DefaultUserSettings with StudioWebPortal set to 'ENABLED' and DefaultLandingUri set to 'studio::' to use the new Studio experience.`
            );
        }

        const defaultUserSettings = resource.Properties.DefaultUserSettings;

        // If DefaultUserSettings is not specified, we can't determine the experience
        if (!defaultUserSettings) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}`,
                `Add DefaultUserSettings property with StudioWebPortal set to 'ENABLED' and DefaultLandingUri set to 'studio::' to explicitly configure the new Studio experience.`
            );
        }

        const resolver = new CloudFormationResolver(allResources);

        // Check StudioWebPortal setting
        const studioWebPortal = defaultUserSettings.StudioWebPortal;
        const defaultLandingUri = defaultUserSettings.DefaultLandingUri;

        let studioWebPortalResolved = null;
        let defaultLandingUriResolved = null;

        // Resolve StudioWebPortal if present
        if (studioWebPortal !== undefined) {
            const resolvedPortal = resolver.resolve<string>(studioWebPortal);

            if (resolvedPortal.isResolved) {
                studioWebPortalResolved = resolvedPortal.value;
            } else {
                // Can't resolve - flag as potential issue
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}`,
                    `Set StudioWebPortal to an explicit string value ('ENABLED') rather than using CloudFormation functions that cannot be validated at scan time.`
                );
            }
        }

        // Resolve DefaultLandingUri if present
        if (defaultLandingUri !== undefined) {
            const resolvedUri = resolver.resolve<string>(defaultLandingUri);
            if (resolvedUri.isResolved) {
                defaultLandingUriResolved = resolvedUri.value;
            } else {
                // Can't resolve - flag as potential issue
                return this.createScanResult(
                    resource,
                    stackName,
                    `${this.description}`,
                    `Set DefaultLandingUri to an explicit string value ('studio::') rather than using CloudFormation functions that cannot be validated at scan time.`
                );
            }
        }

        // Check for explicit Studio Classic configuration
        if (studioWebPortalResolved === 'DISABLED') {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}. StudioWebPortal is explicitly set to 'DISABLED' which indicates Studio Classic`,
                `Set StudioWebPortal to 'ENABLED' and DefaultLandingUri to 'studio::' to use the new Studio experience with enhanced resource isolation.`
            );
        }

        if (defaultLandingUriResolved && defaultLandingUriResolved.startsWith('app:JupyterServer::')) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}. DefaultLandingUri is set to '${defaultLandingUriResolved}' which indicates Studio Classic`,
                `Set DefaultLandingUri to 'studio::' and ensure StudioWebPortal is 'ENABLED' to use the new Studio experience with enhanced resource isolation.`
            );
        }

        // Check for missing or incorrect new Studio configuration
        if (studioWebPortal === undefined && defaultLandingUri === undefined) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}. Neither StudioWebPortal nor DefaultLandingUri are specified, which may default to Studio Classic`,
                `Add StudioWebPortal: 'ENABLED' and DefaultLandingUri: 'studio::' to explicitly configure the new Studio experience.`
            );
        }

        // Check for incomplete new Studio configuration
        if (studioWebPortalResolved === 'ENABLED' && defaultLandingUriResolved !== 'studio::') {
            let actionMessage = `${this.description}. StudioWebPortal is 'ENABLED' but DefaultLandingUri is not set to 'studio::'.`;

            if (defaultLandingUriResolved) {
                actionMessage += ` Current value is '${defaultLandingUriResolved}'.`;
            } else {
                actionMessage += ` DefaultLandingUri is not specified.`;
            }

            const fixMessage = `Set DefaultLandingUri to 'studio::' to complete the new Studio experience configuration.`;

            return this.createScanResult(
                resource,
                stackName,
                actionMessage,
                fixMessage
            );
        }

        // Check if only DefaultLandingUri is set but StudioWebPortal is missing
        if (defaultLandingUriResolved === 'studio::' && studioWebPortal === undefined) {
            return this.createScanResult(
                resource,
                stackName,
                `${this.description}. DefaultLandingUri is set to 'studio::' but StudioWebPortal is not specified`,
                `Add StudioWebPortal: 'ENABLED' to complete the new Studio experience configuration.`
            );
        }

        // If we reach here, the configuration appears correct for new Studio experience
        // (StudioWebPortal is 'ENABLED' and DefaultLandingUri is 'studio::' or not conflicting)
        return null;
    }
}

export default new SageMaker004Rule();