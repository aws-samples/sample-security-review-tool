import path from 'path';
import { License, SourceFile } from './types.js';
import { FileTypeClassifier } from './file-type-classifier.js';
import { HeaderDetector } from './header-detector.js';
import { NodeFileReader } from '../../shared/file-system/node-file-reader.js';
import { GlobFileDiscovery } from '../../shared/file-system/glob-file-discovery.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class LicenseHeaderScanner {
    private readonly fileTypeClassifier = new FileTypeClassifier();
    private readonly headerDetector = new HeaderDetector();
    private readonly fileReader = new NodeFileReader();
    private readonly fileDiscovery: GlobFileDiscovery;
    private readonly context: ProjectContext;

    constructor(context: ProjectContext) {
        this.context = context;
        this.fileDiscovery = new GlobFileDiscovery(context);
    }

    public async loadSourceFiles(): Promise<SourceFile[]> {
        const extensions = this.fileTypeClassifier.getSupportedExtensions();
        const ignorePatterns = this.context.getFolderIgnorePatterns();
        const filePaths = await this.fileDiscovery.findFiles(extensions, ignorePatterns);
        const sourceFiles: SourceFile[] = [];

        for (const filePath of filePaths) {
            const content = await this.fileReader.read(filePath);
            const extension = path.extname(filePath).slice(1);
            sourceFiles.push(new SourceFile(filePath, extension, content));
        }

        return sourceFiles;
    }

    public async findFilesWithInvalidHeaders(validLicenses: License[]): Promise<string[]> {
        const sourceFiles = await this.loadSourceFiles();

        const invalidFiles: SourceFile[] = [];
        for (const file of sourceFiles) {
            const header = this.headerDetector.detectHeader(file.content);
            if (header && !this.headerDetector.isValidHeader(header, validLicenses)) {
                invalidFiles.push(file);
            }
        }

        return invalidFiles.map(file => file.path);
    }
}
