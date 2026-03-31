import { glob } from 'glob';
import path from 'path';
import { ProjectContext } from '../project/project-context.js';

export class GlobFileDiscovery {
    constructor(private readonly context: ProjectContext) { }

    public async findFiles(extensions: string[], ignorePatterns: string[]): Promise<string[]> {
        const extensionsGlob = extensions.join(',');
        const searchPattern = path.join(this.context.getProjectRootFolderPath(), `/**/*.{${extensionsGlob}}`).replace(/\\/g, '/');

        const filePaths = await glob(searchPattern, {
            ignore: ignorePatterns,
            nodir: true
        });

        return filePaths;
    }
}
