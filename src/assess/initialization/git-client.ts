import { CommandRunner } from '../../shared/command-execution/command-runner.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import { GitOperationResult } from './types.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class GitClient {
    private readonly commandRunner: CommandRunner;
    private readonly DEFAULT_USER_NAME = 'Developer';
    private readonly DEFAULT_USER_EMAIL = 'dev@localhost';
    private readonly DEFAULT_GITIGNORE_PATTERNS = [
        '# Common patterns',
        'node_modules/',
        '*.log',
        '.env',
        '.DS_Store',
        'Thumbs.db',
    ];

    constructor(private readonly context: ProjectContext) {
        this.commandRunner = new CommandRunner();
    }

    public async isRepository(): Promise<boolean> {
        try {
            await fs.access(path.join(this.context.getProjectRootFolderPath(), '.git'));
            return true;
        } catch {
            return false;
        }
    }

    public async initialize(): Promise<GitOperationResult> {
        try {
            await this.commandRunner.exec('git init', this.context.getProjectRootFolderPath());
            return { success: true, message: 'Repository initialized' };
        } catch (error) {
            return { success: false, message: `Failed to initialize repository: ${error}` };
        }
    }

    public async ensureUserConfig(): Promise<GitOperationResult> {
        try {
            await this.commandRunner.exec('git config user.name', process.cwd(), true);
            return { success: true, message: 'Git config already set' };
        } catch {
            try {
                await this.commandRunner.exec(
                    `git config --global user.name "${this.DEFAULT_USER_NAME}"`,
                    process.cwd()
                );
                await this.commandRunner.exec(
                    `git config --global user.email "${this.DEFAULT_USER_EMAIL}"`,
                    process.cwd()
                );
                return { success: true, message: 'Default Git config set' };
            } catch (error) {
                return { success: false, message: `Failed to set Git config: ${error}` };
            }
        }
    }

    public async stageAllFiles(): Promise<GitOperationResult> {
        try {
            await this.commandRunner.exec('git add .', this.context.getProjectRootFolderPath());
            return { success: true, message: 'Files staged' };
        } catch (error) {
            return { success: false, message: `Failed to stage files: ${error}` };
        }
    }

    public async commit(message: string): Promise<GitOperationResult> {
        try {
            await this.commandRunner.exec(`git commit -m "${message}"`, this.context.getProjectRootFolderPath());
            return { success: true, message: 'Commit created' };
        } catch (error) {
            return { success: false, message: `Failed to create commit: ${error}` };
        }
    }

    public async ensureGitignoreExists(patterns?: string[]): Promise<GitOperationResult> {
        try {
            const gitignorePath = path.join(this.context.getProjectRootFolderPath(), '.gitignore');
            const hasExisting = await this.hasGitignore();

            if (hasExisting) {
                return { success: true, message: '.gitignore already exists' };
            }

            const patternsToWrite = patterns || this.DEFAULT_GITIGNORE_PATTERNS;
            await fs.writeFile(gitignorePath, patternsToWrite.join('\n') + '\n');
            return { success: true, message: '.gitignore created' };
        } catch (error) {
            return { success: false, message: `Failed to create .gitignore: ${error}` };
        }
    }

    private async hasGitignore(): Promise<boolean> {
        try {
            const gitignorePath = path.join(this.context.getProjectRootFolderPath(), '.gitignore');
            const content = await fs.readFile(gitignorePath, 'utf-8');
            return content.trim().length > 0;
        } catch {
            return false;
        }
    }
}
