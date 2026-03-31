import { SRTConfig } from './config-manager.js';
import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';

export interface ValidationResult {
    isValid: boolean;
    value: string;
    displayName?: string;
    error?: string;
    helpUrl?: string;
}

export interface ValidationResults {
    region: ValidationResult;
    model: ValidationResult;
    profile: ValidationResult;
    hasErrors: boolean;
}

export class ConfigValidator {
    async validateConfiguration(config: SRTConfig): Promise<ValidationResults> {

        BedrockConfig.initialize(config.AWS_PROFILE, config.AWS_REGION);
        const model = BedrockConfig.getModel();
        
        const results: ValidationResults = {
            region: { isValid: true, value: config.AWS_REGION },
            model: { isValid: false, value: model.id },
            profile: { isValid: false, value: config.AWS_PROFILE },
            hasErrors: false
        };

        // Validate profile first (needed for other validations)
        results.profile = await this.validateProfile(config.AWS_PROFILE, config.AWS_REGION);

        // Only validate model if profile is valid
        if (results.profile.isValid) {
            results.model = await this.validateModel(model, config.AWS_REGION, config.AWS_PROFILE);
        } else {
            results.model = {
                isValid: false,
                value: model.id,
                displayName: model.name,
                error: 'Cannot validate model - profile validation failed'
            };
        }

        results.hasErrors = !results.region.isValid || !results.model.isValid || !results.profile.isValid;

        return results;
    }
    
    private async validateProfile(profileName: string, region: string): Promise<ValidationResult> {
        try {
            const credentials = fromNodeProviderChain(profileName !== 'default' ? { profile: profileName } : {});
            const client = new BedrockRuntimeClient({
                region: region,
                credentials: credentials
            });

            // Test if profile has basic AWS access
            await client.config.credentials();

            return {
                isValid: true,
                value: profileName
            };
        } catch (error) {
            let errorMessage = 'Profile validation failed';

            if (error instanceof Error) {
                if (error.message.includes('could not be found')) {
                    errorMessage = 'Profile not found in AWS credentials';
                } else if (error.message.includes('Unable to load credentials')) {
                    errorMessage = 'Unable to load credentials from profile';
                } else {
                    errorMessage = `Profile error: ${error.message}`;
                }
            }

            return {
                isValid: false,
                value: profileName,
                error: errorMessage
            };
        }
    }

    private async validateModel(model: { id: string; name: string }, region: string, profileName: string): Promise<ValidationResult> {
        try {
            const credentials = fromNodeProviderChain(profileName !== 'default' ? { profile: profileName } : {});

            try {
                const runtimeClient = new BedrockRuntimeClient({
                    region: region,
                    credentials: credentials,
                    requestHandler: new FetchHttpHandler()
                });

                const converseCommand = new ConverseCommand({
                    modelId: BedrockConfig.getModelIdWithInferenceProfilePrefix(),
                    messages: [{ role: "user", content: [{ text: "Hello" }] }]
                });

                await runtimeClient.send(converseCommand);

                return {
                    isValid: true,
                    value: model.id,
                    displayName: model.name
                };
            } catch (invokeError) {
                return {
                    isValid: false,
                    value: model.id,
                    displayName: model.name,
                    error: `${model.name} cannot be invoked. Ensure your AWS Profile has the "bedrock:InvokeModel" permission and try again.`
                };
            }

        } catch (error) {
            return {
                isValid: false,
                value: model.id,
                displayName: model.name,
                error: `Model validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
            };
        }
    }
}