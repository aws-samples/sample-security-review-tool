import { createHash, randomUUID } from 'crypto';
import { CommandRunner } from '../command-execution/command-runner.js';

export type ProjectIdSource = 'Git' | 'Random';

export interface ProjectIdResult {
    id: string;
    source: ProjectIdSource;
}

export class ProjectIdGenerator {
    private readonly commandRunner = new CommandRunner();

    public async generate(projectPath: string): Promise<ProjectIdResult> {
        const remoteUrl = await this.getGitRemoteUrl(projectPath);

        if (remoteUrl) {
            return {
                id: this.hashRemoteUrl(remoteUrl),
                source: 'Git'
            };
        }

        return {
            id: randomUUID(),
            source: 'Random'
        };
    }

    private async getGitRemoteUrl(projectPath: string): Promise<string | null> {
        try {
            const stdout = await this.commandRunner.exec(
                'git config --get remote.origin.url',
                projectPath,
                true
            );
            const url = stdout.trim();
            return url || null;
        } catch {
            return null;
        }
    }

    private hashRemoteUrl(url: string): string {
        const normalized = this.normalizeGitUrl(url);
        return createHash('sha256').update(normalized).digest('hex').substring(0, 32);
    }

    private normalizeGitUrl(url: string): string {
        return url
            .replace(/\.git$/, '')
            .replace(/^git@([^:]+):/, 'https://$1/')
            .replace(/^ssh:\/\/git@/, 'https://')
            .toLowerCase();
    }
}
