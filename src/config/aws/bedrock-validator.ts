import { BedrockRuntimeClient, ConverseCommand } from '@aws-sdk/client-bedrock-runtime';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { FetchHttpHandler } from '@aws-sdk/fetch-http-handler';
import { ValidationResult } from './types.js';
import { BedrockConfig } from './bedrock-config.js';

export class BedrockValidator {
  public async validate(profile: string, region: string): Promise<ValidationResult> {
    BedrockConfig.initialize(profile, region);
    const model = BedrockConfig.getModel();

    const result: ValidationResult = {
      isValid: false,
      validCredentials: false,
      hasBedrockAccess: false,
      modelAccessible: false,
      errors: []
    };

    // Validate profile first (needed for other validations)
    const profileValid = await this.validateProfile(profile, region);
    if (!profileValid.isValid) {
      result.errors.push(profileValid.error || 'Profile validation failed');
      return result;
    }

    result.validCredentials = true;
    result.credentialSource = profileValid.credentialSource;

    // Validate model access
    const modelValid = await this.validateModel(model, region, profile);
    if (!modelValid.isValid) {
      result.errors.push(modelValid.error || 'Model validation failed');
      return result;
    }

    result.hasBedrockAccess = true;
    result.modelAccessible = true;
    result.isValid = true;

    return result;
  }

  private async validateProfile(
    profileName: string,
    region: string
  ): Promise<{ isValid: boolean; error?: string; credentialSource?: string }> {
    try {
      const credentials = fromNodeProviderChain(profileName !== 'default' ? { profile: profileName } : {});
      const client = new BedrockRuntimeClient({
        region: region,
        credentials: credentials
      });

      // Test if profile has basic AWS access
      const resolved = await client.config.credentials();
      const source = resolved.accessKeyId?.startsWith('ASIA') ? 'temporary credentials (STS/SSO/federation)' : 'static credentials (IAM user)';

      return { isValid: true, credentialSource: source };
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
        error: errorMessage
      };
    }
  }

  private async validateModel(
    model: { id: string; name: string },
    region: string,
    profileName: string
  ): Promise<{ isValid: boolean; error?: string }> {
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
          messages: [{ role: 'user', content: [{ text: 'Hello' }] }]
        });

        await runtimeClient.send(converseCommand);

        return { isValid: true };
      } catch (invokeError) {
        const errorDetail = invokeError instanceof Error ? invokeError.message : String(invokeError);
        return {
          isValid: false,
          error: `${model.name} cannot be invoked: ${errorDetail}`
        };
      }
    } catch (error) {
      return {
        isValid: false,
        error: `Model validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }
}
