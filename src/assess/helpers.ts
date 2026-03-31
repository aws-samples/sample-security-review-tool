import { LicenseHeaderCheckResult } from './types.js';
import { LicenseHeaderScanner } from './licensing/license-header-scanner.js';
import { LicenseRegistry } from './licensing/license-registry.js';
import { ProjectSettingsManager } from '../shared/project/project-settings-manager.js';
import { ProjectContext } from '../shared/project/project-context.js';
import { IgnorePatternService } from '../shared/file-system/ignore-pattern-service.js';

export class AssessHelpers {
    public static async getProjectLicense(projectRootFolderPath: string): Promise<string | undefined> {
        const ignorePatternService = await IgnorePatternService.create(projectRootFolderPath);
        const context = new ProjectContext(projectRootFolderPath, ignorePatternService);
        const settingsManager = new ProjectSettingsManager(context);
        const settings = await settingsManager.loadSettings();
        return settings?.LICENSE;
    }

    public static async checkForExistingLicenseHeaders(projectRootFolderPath: string): Promise<LicenseHeaderCheckResult> {
        const ignorePatternService = await IgnorePatternService.create(projectRootFolderPath);
        const context = new ProjectContext(projectRootFolderPath, ignorePatternService);
        const licenseRegistry = new LicenseRegistry();
        const validLicenses = licenseRegistry.getAllLicenses();
        const scanner = new LicenseHeaderScanner(context);
        const nonConformingFiles = await scanner.findFilesWithInvalidHeaders(validLicenses);
        return { hasExistingHeaders: nonConformingFiles.length > 0, fileCount: nonConformingFiles.length };
    }
}