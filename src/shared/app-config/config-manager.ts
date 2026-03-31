import fs from 'fs/promises';
import path from 'path';
import { AppPaths } from './app-paths.js';
import { SrtLogger } from '../logging/srt-logger.js';

export interface SRTConfig {
    AWS_REGION: string;
    AWS_PROFILE: string;
    TELEMETRY_ENABLED: boolean;
}

export class ConfigManager {
    private configPath: string;

    constructor() {
        this.configPath = path.join(AppPaths.getAppDir(), 'srtconfig.json');
    }

    public async loadConfig(): Promise<SRTConfig | null> {
        try {
            const configData = await fs.readFile(this.configPath, 'utf8');
            const config = JSON.parse(configData) as SRTConfig;

            if (!config.AWS_REGION || !config.AWS_PROFILE || config.TELEMETRY_ENABLED === undefined) {
                return null;
            }

            return config;
        } catch (error) {
            return null;
        }
    }

    public async saveConfig(config: SRTConfig): Promise<void> {
        try {
            const configJson = JSON.stringify(config, null, 2);
            await fs.writeFile(this.configPath, configJson, 'utf8');
        } catch (error) {
            SrtLogger.logError('Failed to save config', error as Error, { configPath: this.configPath });
            throw new Error(`Failed to save configuration: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    public getConfigPath(): string {
        return this.configPath;
    }

    public async configExists(): Promise<boolean> {
        try {
            await fs.access(this.configPath);
            return true;
        } catch {
            return false;
        }
    }
}