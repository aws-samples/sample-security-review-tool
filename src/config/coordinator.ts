import { AwsEnvironmentSetup } from './aws/aws-setup.js';
import { PathInstallationSetup } from './path/path-setup.js';
import { AwsProfile, ValidationResult } from './aws/types.js';
import { SRTConfig } from '../shared/app-config/config-manager.js';
import { PathCheckResult, PathUpdateResult } from './path/path-setup.js';
import { ScannerSetup } from './scanner/scanner-setup.js';
import { PrerequisiteInstallStatus } from './types.js';

export class ConfigCoordinator {
    private readonly awsSetup = new AwsEnvironmentSetup();
    private readonly pathSetup = new PathInstallationSetup();
    private readonly scannerSetup: ScannerSetup;

    constructor(private readonly onProgress: (progress: string) => void = () => { }) {
        this.scannerSetup = new ScannerSetup(onProgress);
     }

    public async discoverProfiles(): Promise<AwsProfile[]> {
        const profiles = await this.awsSetup.discoverProfiles();
        return profiles;
    }

    public async loadExistingConfig(): Promise<SRTConfig | null> {
        const config = await this.awsSetup.loadExistingConfig();
        return config;
    }

    public determineDefaultProfile(profiles: AwsProfile[]): AwsProfile | undefined {
        const defaultProfile = this.awsSetup.determineDefaultProfile(profiles);
        return defaultProfile;
    }

    public checkPath(): PathCheckResult {
        const result = this.pathSetup.checkPath();
        return result;
    }

    public async updatePath(): Promise<PathUpdateResult> {
        const result = await this.pathSetup.updatePath();
        return result;
    }

    public getRestartInstructions(): string[] {
        return this.pathSetup.getRestartInstructions();
    }

    public async validateAndSave(profile: string, region: string, telemetryEnabled: boolean): Promise<ValidationResult> {
        const result = await this.awsSetup.validateAndSave(profile, region, telemetryEnabled);
        return result;
    }

    public async checkPrerequisitesInstalled(): Promise<boolean> {
        return this.scannerSetup.checkAllInstalled();
    }

    public async installPrerequisites(forceReinstall: boolean): Promise<PrerequisiteInstallStatus> {
        const result = await this.scannerSetup.installMissingScanners(forceReinstall);

        if (result.noneInstalled) {
            return { status: 'SKIPPED' };
        }

        if (result.success) {
            return { status: 'SUCCESS' };
        }

        return { status: 'ERROR', errors: result.errors };
    }
}
