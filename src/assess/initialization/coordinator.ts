import { ProjectContext } from '../../shared/project/project-context.js';
import { ProjectInitializer } from './project-initializer.js';
import { GitInitializer } from './git-initializer.js';
import { CdkInitializer } from './cdk-initializer.js';

export class InitializationCoordinator {
    constructor(private context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) { }

    public async initialize(): Promise<void> {
        const projectInit = new ProjectInitializer(this.context, this.onProgress);
        await projectInit.initialize();

        const gitInit = new GitInitializer(this.context, this.onProgress);
        await gitInit.initialize();

        const cdkInit = new CdkInitializer(this.context, this.onProgress);
        await cdkInit.initialize();
    }
}
