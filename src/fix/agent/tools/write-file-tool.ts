import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';
import { EditRecorder } from '../edit-recorder.js';
import { NodeFileReader } from '../../../shared/file-system/node-file-reader.js';

/**
 * Writes an entire file. Use for creating new files or when the change is
 * large enough that a literal edit_file replacement is unwieldy. The write is
 * staged via the EditRecorder — not flushed to disk by this tool — so the
 * coordinator can still preview and confirm.
 */
export class WriteFileTool implements AgentTool {
    private readonly fileReader = new NodeFileReader();

    constructor(
        private readonly guard: WorkspaceGuard,
        private readonly editRecorder: EditRecorder,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'write_file',
            description: 'Create a new file or overwrite an existing file with the given content. Prefer edit_file for small changes to existing files.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        path: { type: 'string', description: 'Path relative to the project root.' },
                        content: { type: 'string', description: 'Full file content to write.' },
                    },
                    required: ['path', 'content'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const requestedPath = String(input.path ?? '');
        const content = String(input.content ?? '');

        if (!requestedPath) {
            return { text: 'Error: "path" is required.', isError: true };
        }

        try {
            const absolutePath = this.guard.resolve(requestedPath);
            const existingContent = await this.fileReader.readTextFile(absolutePath);
            this.editRecorder.recordOriginal(absolutePath, existingContent ?? '', existingContent !== null);
            this.editRecorder.recordUpdate(absolutePath, content);

            return {
                json: {
                    path: requestedPath,
                    isNewFile: existingContent === null,
                    byteLength: content.length,
                },
            };
        } catch (error) {
            return { text: (error as Error).message, isError: true };
        }
    }
}
