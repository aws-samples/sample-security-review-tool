import { glob } from 'glob';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';

const MAX_RESULTS = 500;

export class ListFilesTool implements AgentTool {
    constructor(
        private readonly context: ProjectContext,
        private readonly guard: WorkspaceGuard,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'list_files',
            description: 'List files matching a glob pattern, relative to the project root. Respects the project ignore patterns (.gitignore etc.).',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        pattern: { type: 'string', description: 'Glob pattern, e.g. "lib/**/*.ts".' },
                    },
                    required: ['pattern'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const pattern = String(input.pattern ?? '');
        if (!pattern) {
            return { text: 'Error: "pattern" is required.', isError: true };
        }

        try {
            const matches = await glob(pattern, {
                cwd: this.context.getProjectRootFolderPath(),
                ignore: this.context.getFolderIgnorePatterns(),
                nodir: true,
                maxDepth: 15,
            });

            const truncated = matches.length > MAX_RESULTS;
            const paths = matches.slice(0, MAX_RESULTS).map(p => this.guard.toRelative(
                this.guard.resolve(p),
            ));

            return { json: { files: paths, truncated, total: matches.length } };
        } catch (error) {
            return { text: (error as Error).message, isError: true };
        }
    }
}
