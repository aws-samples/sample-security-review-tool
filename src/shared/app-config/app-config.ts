import { ConfigManager, SRTConfig } from './config-manager.js';
import { BedrockConfig } from '../../config/aws/bedrock-config.js';

export class AppConfig {
    private static instance: SRTConfig | null = null;
    private static loaded = false;

    public static async load(): Promise<SRTConfig | null> {
        if (AppConfig.loaded) {
            return AppConfig.instance;
        }

        const manager = new ConfigManager();
        AppConfig.instance = await manager.loadConfig();
        AppConfig.loaded = true;

        if (AppConfig.instance) {
            BedrockConfig.initialize(AppConfig.instance.AWS_PROFILE, AppConfig.instance.AWS_REGION);
        }

        return AppConfig.instance;
    }

    public static get(): SRTConfig | null {
        return AppConfig.instance;
    }

    public static getInstallationId(): string | undefined {
        return AppConfig.instance?.INSTALLATION_ID;
    }

    public static isTelemetryEnabled(): boolean {
        if (process.env.SRT_TELEMETRY_DISABLED === '1') return false;
        return AppConfig.instance?.TELEMETRY_ENABLED ?? false;
    }
}
