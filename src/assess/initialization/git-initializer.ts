import { GitClient } from './git-client.js';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { ProjectContext } from '../../shared/project/project-context.js';

export class GitInitializer {
    private readonly gitClient: GitClient;

    constructor(private context: ProjectContext, private readonly onProgress: (progress: string) => void) {
        this.gitClient = new GitClient(context);
    }

    public async initialize(): Promise<void> {
        try {
            this.onProgress('  › Started Git initialization...');

            const isRepo = await this.gitClient.isRepository();

            if (!isRepo) {
                await this.initializeRepository();
            }

            this.onProgress('  ✔ Completed Git initialization');
        } catch (error) {
            this.onProgress('  ✗ Failed Git initialization. Proceeding with assessment anyway');
            SrtLogger.logError('Git initialization failed', error as Error, { projectRootFolderPath: this.context });
        }
    }

    private async initializeRepository(): Promise<boolean> {
        const initResult = await this.gitClient.initialize();
        if (!initResult.success) return false;

        const configResult = await this.gitClient.ensureUserConfig();
        if (!configResult.success) return false;

        const gitignoreResult = await this.gitClient.ensureGitignoreExists();
        if (!gitignoreResult.success) return false;

        const stageResult = await this.gitClient.stageAllFiles();
        if (!stageResult.success) return false;

        const commitResult = await this.gitClient.commit(
            'feat: initial project setup'
        );        
        if (!commitResult.success) return false;

        return true;
    }
}
