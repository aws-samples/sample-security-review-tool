import { glob } from 'glob';
import { ProjectContext } from '../../../shared/project/project-context.js';
import { NodeFileReader } from '../../../shared/file-system/node-file-reader.js';
import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';

interface GrepHit {
    path: string;
    line: number;
    text: string;
}

const MAX_HITS = 200;

export class GrepTool implements AgentTool {
    private readonly fileReader = new NodeFileReader();

    constructor(
        private readonly context: ProjectContext,
        private readonly guard: WorkspaceGuard,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'grep',
            description: 'Search for a regular expression across files in the project. Returns matching lines with their paths and line numbers.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        pattern: { type: 'string', description: 'Regular expression (JavaScript syntax).' },
                        pathGlob: { type: 'string', description: 'Optional glob to restrict the search, e.g. "lib/**/*.ts".' },
                    },
                    required: ['pattern'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const pattern = String(input.pattern ?? '');
        const pathGlob = typeof input.pathGlob === 'string' ? input.pathGlob : '**/*';

        if (!pattern) {
            return { text: 'Error: "pattern" is required.', isError: true };
        }

        let regex: RegExp;
        try {
            regex = new RegExp(pattern);
        } catch (error) {
            return { text: `Invalid regex: ${(error as Error).message}`, isError: true };
        }

        const root = this.context.getProjectRootFolderPath();
        const files = await glob(pathGlob, {
            cwd: root,
            ignore: this.context.getFolderIgnorePatterns(),
            nodir: true,
            maxDepth: 15,
        });

        const hits = await this.searchFiles(files, regex);
        const truncated = hits.length > MAX_HITS;
        return { json: { hits: hits.slice(0, MAX_HITS), truncated, total: hits.length } };
    }

    private async searchFiles(relativePaths: string[], regex: RegExp): Promise<GrepHit[]> {
        const hits: GrepHit[] = [];
        for (const relativePath of relativePaths) {
            if (hits.length >= MAX_HITS) break;
            const absolute = this.guard.resolve(relativePath);
            const content = await this.fileReader.readTextFile(absolute);
            if (content === null) continue;
            this.collectHits(content, relativePath, regex, hits);
        }
        return hits;
    }

    private collectHits(content: string, relativePath: string, regex: RegExp, hits: GrepHit[]): void {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            if (regex.test(lines[i])) {
                hits.push({ path: relativePath, line: i + 1, text: lines[i].slice(0, 400) });
                if (hits.length >= MAX_HITS) return;
            }
        }
    }
}
