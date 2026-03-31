import { BedrockValidator } from './bedrock-validator.js';
import { AwsCredentialsFileReader } from './credentials-reader.js';
import { ConfigManager, SRTConfig } from '../../shared/app-config/config-manager.js';
import { AwsProfile, ValidationResult } from './types.js';

export interface AwsEnvironmentSetupResult {
  profiles: AwsProfile[];
  selectedProfile?: string;
  selectedRegion?: string;
  validationResult?: ValidationResult;
  saved: boolean;
}

export class AwsEnvironmentSetup {
  private profileRepository = new AwsCredentialsFileReader();
  private configRepository = new ConfigManager();
  private bedrockValidator = new BedrockValidator();

  public async discoverProfiles(): Promise<AwsProfile[]> {
    return await this.profileRepository.discoverProfiles();
  }

  public async loadExistingConfig(): Promise<SRTConfig | null> {
    return this.configRepository.loadConfig();
  }

  public async validateAndSave(profile: string, region: string, telemetryEnabled: boolean): Promise<ValidationResult> {
    const validationResult = await this.bedrockValidator.validate(profile, region);

    if (validationResult.isValid) {
      const config: SRTConfig = {
        AWS_PROFILE: profile,
        AWS_REGION: region,
        TELEMETRY_ENABLED: telemetryEnabled
      };
      await this.configRepository.saveConfig(config);
    }

    return validationResult;
  }

  public getConfigPath(): string {
    return this.configRepository.getConfigPath();
  }

  public determineDefaultProfile(profiles: AwsProfile[]): AwsProfile | undefined {
    return profiles.find(p => p.isDefault) || profiles[0];
  }
}
