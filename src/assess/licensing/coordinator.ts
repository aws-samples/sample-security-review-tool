import path from 'path';
import { License, SourceFile } from './types.js';
import { FileTypeClassifier } from './file-type-classifier.js';
import { HeaderDetector } from './header-detector.js';
import { HeaderFormatter } from './header-formatter.js';
import { NodeFileWriter } from '../../shared/file-system/node-file-writer.js';
import { ProjectContext } from '../../shared/project/project-context.js';
import { ProjectSettingsManager } from '../../shared/project/project-settings-manager.js';
import { LicenseRegistry } from './license-registry.js';
import { LicenseHeaderScanner } from './license-header-scanner.js';

export class LicenseComplianceCoordinator {
    private readonly fileTypeClassifier = new FileTypeClassifier();
    private readonly headerDetector = new HeaderDetector();
    private readonly headerFormatter = new HeaderFormatter();
    private readonly fileWriter = new NodeFileWriter();
    private readonly licenseRegistry = new LicenseRegistry();
    private readonly scanner: LicenseHeaderScanner;
    private readonly projectSettingsManager: ProjectSettingsManager;
    private readonly licenseObj: License;

    constructor(private readonly context: ProjectContext, private readonly license: string) {
        this.scanner = new LicenseHeaderScanner(context);
        this.projectSettingsManager = new ProjectSettingsManager(context);

        this.licenseObj = this.licenseRegistry.getLicense(license);
    }

    public async execute(): Promise<void> {
        await this.saveProjectLicense();
        await this.writeLicenseFile();
        await this.writeNoticeFile();
        await this.updateFileHeaders();
    }

    private async saveProjectLicense(): Promise<void> {
        const projectSettings = await this.projectSettingsManager.loadSettings();
        projectSettings.LICENSE = this.license;
        await this.projectSettingsManager.saveSettings(projectSettings);
    }

    private async writeLicenseFile(): Promise<void> {
        const licensePath = path.join(this.context.getProjectRootFolderPath(), 'LICENSE');
        await this.fileWriter.write(licensePath, this.licenseObj.licenseContent);
    }

    private async writeNoticeFile(): Promise<void> {
        const noticePath = path.join(this.context.getProjectRootFolderPath(), 'NOTICE');
        await this.fileWriter.write(noticePath, this.licenseObj.noticeContent);
    }

    private async updateFileHeaders(): Promise<void> {
        const sourceFiles = await this.scanner.loadSourceFiles();
        
        for (const sourceFile of sourceFiles) {
            await this.updateFileHeader(sourceFile);
        }
    }

    private async updateFileHeader(sourceFile: SourceFile): Promise<void> {
        let updatedContent = this.headerDetector.removeAllHeaders(sourceFile.content);

        const commentFormat = this.fileTypeClassifier.classifyByExtension(sourceFile.extension);
        const formattedHeader = this.headerFormatter.format(this.licenseObj, commentFormat);
        updatedContent = this.headerFormatter.insertIntoFile(updatedContent, formattedHeader);

        if (updatedContent !== sourceFile.content) {
            await this.fileWriter.write(sourceFile.path, updatedContent);
        }
    }
}
