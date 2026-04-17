import { NodeFileReader } from '../../../shared/file-system/node-file-reader.js';
import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';
import { EditRecorder } from '../edit-recorder.js';

const MAX_BYTES = 200_000;

export class ReadFileTool implements AgentTool {
    private readonly fileReader = new NodeFileReader();

    constructor(
        private readonly guard: WorkspaceGuard,
        private readonly editRecorder: EditRecorder,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'read_file',
            description: 'Read the UTF-8 contents of a file relative to the project root. Returns the current proposed contents if the file has been edited earlier in this session.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        path: { type: 'string', description: 'Path relative to the project root.' },
                    },
                    required: ['path'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const requestedPath = String(input.path ?? '');
        if (!requestedPath) {
            return { text: 'Error: "path" is required.', isError: true };
        }

        try {
            const absolutePath = this.guard.resolve(requestedPath);
            const pendingContent = this.editRecorder.getCurrentContent(absolutePath);
            if (pendingContent !== undefined) {
                return this.formatContent(requestedPath, pendingContent);
            }

            const content = await this.fileReader.readTextFile(absolutePath);
            if (content === null) {
                return { text: `File not found: ${requestedPath}`, isError: true };
            }

            this.editRecorder.recordOriginal(absolutePath, content);
            return this.formatContent(requestedPath, content);
        } catch (error) {
            return { text: (error as Error).message, isError: true };
        }
    }

    private formatContent(displayPath: string, content: string): ToolOutput {
        if (content.length > MAX_BYTES) {
            return {
                text: `File ${displayPath} is too large (${content.length} bytes). Use grep to search for specific sections.`,
                isError: true,
            };
        }
        return { json: { path: displayPath, content } };
    }
}
