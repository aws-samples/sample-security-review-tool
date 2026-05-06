import { AwsEnvironmentSetup } from './aws/aws-setup.js';
import { PathInstallationSetup } from './path/path-setup.js';
import { AwsProfile, ValidationResult } from './aws/types.js';
import { SRTConfig } from '../shared/app-config/config-manager.js';
import { PathCheckResult, PathUpdateResult } from './path/path-setup.js';

export class ConfigCoordinator {
    private readonly awsSetup = new AwsEnvironmentSetup();
    private readonly pathSetup = new PathInstallationSetup();

    constructor(private readonly onProgress: (progress: string) => void = () => { }) { }

    public async discoverProfiles(): Promise<AwsProfile[]> {
        return this.awsSetup.discoverProfiles();
    }

    public async loadExistingConfig(): Promise<SRTConfig | null> {
        return this.awsSetup.loadExistingConfig();
    }

    public determineDefaultProfile(profiles: AwsProfile[]): AwsProfile | undefined {
        return this.awsSetup.determineDefaultProfile(profiles);
    }

    public checkPath(): PathCheckResult {
        return this.pathSetup.checkPath();
    }

    public async updatePath(): Promise<PathUpdateResult> {
        return this.pathSetup.updatePath();
    }

    public getRestartInstructions(): string[] {
        return this.pathSetup.getRestartInstructions();
    }

    public async validateAndSave(profile: string, region: string, telemetryEnabled: boolean): Promise<ValidationResult> {
        return this.awsSetup.validateAndSave(profile, region, telemetryEnabled);
    }
}
