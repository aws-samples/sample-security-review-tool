import * as fs from 'fs/promises';
import { ProjectContext } from '../../shared/project/project-context.js';

export class ProjectInitializer {
    private readonly OUTPUT_FOLDER_NAME = '.srt';

    constructor(private context: ProjectContext, private readonly onProgress: (progress: string) => void = () => { }) { }

    public async initialize(): Promise<void> {
        this.onProgress('  › Configuring output folder...');

        try {
            await fs.stat(this.context.getSrtOutputFolderPath());
        } catch {
            await fs.mkdir(this.context.getSrtOutputFolderPath(), { recursive: true });
        }

        this.onProgress('  ✔ Configured output folder');
    }
}
