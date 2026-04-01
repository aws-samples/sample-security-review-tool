import fs from 'fs/promises';
import path from 'path';
import { SrtLogger } from '../logging/srt-logger.js';
import { ProjectContext } from './project-context.js';
import { ProjectIdGenerator, ProjectIdSource } from './project-id-generator.js';

export interface ProjectSettings {
    LICENSE?: string;
    LAST_SCAN_DATE?: string;
    PROJECT_ID?: string;
    PROJECT_ID_SOURCE?: ProjectIdSource;
}

export class ProjectSettingsManager {
    constructor(private readonly context: ProjectContext) { }

    private getSettingsFilePath(): string {
        return path.join(this.context.getSrtOutputFolderPath(), 'settings.json');
    }

    public async loadSettings(): Promise<ProjectSettings> {
        const settingsFilePath = this.getSettingsFilePath();

        try {
            const settingsData = await fs.readFile(settingsFilePath, 'utf8');
            return JSON.parse(settingsData) as ProjectSettings;
        } catch (error) {          
            return {} as ProjectSettings; 
        }
    }

    public async saveSettings(config: ProjectSettings): Promise<void> {
        const settingsFilePath = this.getSettingsFilePath();

        try {
            const settingsJson = JSON.stringify(config, null, 2);
            await fs.mkdir(path.dirname(settingsFilePath), { recursive: true });
            await fs.writeFile(settingsFilePath, settingsJson, 'utf8');
        } catch (error) {
            SrtLogger.logError('Failed to save settings', error as Error, { settingsFilePath });
            throw new Error(`Failed to save settings: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    public async updateLastScanDate(): Promise<void> {
        try {
            const settings = await this.loadSettings() || {} as ProjectSettings;
            settings.LAST_SCAN_DATE = new Date().toISOString();
            await this.saveSettings(settings);
        } catch (error) {
            // Silent fail on last scan date update
        }
    }

    public async ensureProjectId(): Promise<string> {
        const settings = await this.loadSettings();

        if (settings.PROJECT_ID) {
            return settings.PROJECT_ID;
        }

        const generator = new ProjectIdGenerator();
        const result = await generator.generate(this.context.getProjectRootFolderPath());

        settings.PROJECT_ID = result.id;
        settings.PROJECT_ID_SOURCE = result.source;
        await this.saveSettings(settings);

        return result.id;
    }
}
