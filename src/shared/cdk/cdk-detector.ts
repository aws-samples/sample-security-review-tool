import * as fs from 'fs/promises';
import * as path from 'path';
import { glob } from 'glob';
import { CdkCommandParser } from './cdk-command-parser.js';
import { ProjectContext } from '../project/project-context.js';
import { CdkProjectConfig } from './types.js';

export class CdkDetector {
    private readonly cdkCommandParser = new CdkCommandParser();

    constructor(private readonly context: ProjectContext) {}

    public async getCdkRootFolderPath(): Promise<string | null> {
        try {
            const matches = await glob('**/cdk.json', {
                ignore: this.context.getFolderIgnorePatterns(),
                cwd: this.context.getProjectRootFolderPath(),
                absolute: true,
                maxDepth: 10
            });

            if (matches.length > 0) {
                return path.dirname(matches[0]);
            }

            return null;
        } catch (error) {
            return null;
        }
    }

    public async getCdkOutputFolderPath(): Promise<string | null> {
        try {
            const cdkRoot = await this.getCdkRootFolderPath();

            if (!cdkRoot) return null;

            const cdkJsonPath = path.join(cdkRoot, 'cdk.json');
            const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
            const cdkJson = JSON.parse(cdkJsonContent);
            const outputDir = cdkJson.output || 'cdk.out';
            
            return path.join(cdkRoot, outputDir);
        } catch (error) {
            return null;
        }
    }

    public async getCdkEntrypoint(): Promise<string | null> {
        try {
            const cdkRoot = await this.getCdkRootFolderPath();
            if (!cdkRoot) return null;

            const cdkJsonPath = path.join(cdkRoot, 'cdk.json');
            const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
            const cdkEntrypointFile = this.cdkCommandParser.extractFromCdkJson(cdkJsonContent);

            if (!cdkEntrypointFile) return null;

            return path.join(cdkRoot, cdkEntrypointFile.file);
        } catch (error) {
            return null;
        }
    }

    public async getAllCdkProjects(): Promise<CdkProjectConfig[]> {
        try {
            const matches = await glob('**/cdk.json', {
                ignore: this.context.getFolderIgnorePatterns(),
                cwd: this.context.getProjectRootFolderPath(),
                absolute: true,
                maxDepth: 10
            });

            const projects: CdkProjectConfig[] = [];
            for (const cdkJsonPath of matches) {
                const config = await this.buildCdkProjectConfig(cdkJsonPath);
                if (config) projects.push(config);
            }

            return projects;
        } catch (error) {
            return [];
        }
    }

    private async buildCdkProjectConfig(cdkJsonPath: string): Promise<CdkProjectConfig | null> {
        try {
            const rootPath = path.dirname(cdkJsonPath);
            const name = path.basename(rootPath);
            const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
            const cdkJson = JSON.parse(cdkJsonContent);

            const outputDir = cdkJson.output || 'cdk.out';
            const outputPath = path.join(rootPath, outputDir);

            const cdkEntrypointFile = this.cdkCommandParser.extractFromCdkJson(cdkJsonContent);
            const entrypointPath = cdkEntrypointFile ? path.join(rootPath, cdkEntrypointFile.file) : null;

            return { name, rootPath, outputPath, entrypointPath };
        } catch (error) {
            return null;
        }
    }
}
