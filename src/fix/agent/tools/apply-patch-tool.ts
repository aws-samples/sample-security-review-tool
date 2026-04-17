import { applyPatch } from 'diff';
import { NodeFileReader } from '../../../shared/file-system/node-file-reader.js';
import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';
import { EditRecorder } from '../edit-recorder.js';

/**
 * Applies a unified diff to a file's in-memory contents.
 *
 * The patch is NOT written to disk; it is staged in the EditRecorder so the
 * coordinator can preview and confirm the full set of edits before committing.
 * Subsequent read_file calls will see the patched content.
 */
export class ApplyPatchTool implements AgentTool {
    private readonly fileReader = new NodeFileReader();

    constructor(
        private readonly guard: WorkspaceGuard,
        private readonly editRecorder: EditRecorder,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'apply_patch',
            description: 'Apply a unified diff to a file. The patch must target the file contents as last seen via read_file. Returns an error (not a throw) if the hunks do not apply cleanly, in which case re-read the file and try again.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        path: { type: 'string', description: 'Path relative to the project root.' },
                        patch: { type: 'string', description: 'Unified diff (including --- / +++ / @@ headers).' },
                    },
                    required: ['path', 'patch'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const requestedPath = String(input.path ?? '');
        const patch = String(input.patch ?? '');

        if (!requestedPath || !patch) {
            return { text: 'Error: "path" and "patch" are both required.', isError: true };
        }

        try {
            const absolutePath = this.guard.resolve(requestedPath);
            const currentContent = await this.loadCurrentContent(absolutePath);
            const patched = applyPatch(currentContent, patch);

            if (patched === false) {
                return {
                    text: 'Patch did not apply cleanly. Re-read the file and emit a patch against its exact current contents.',
                    isError: true,
                };
            }

            this.editRecorder.recordOriginal(absolutePath, currentContent);
            this.editRecorder.recordUpdate(absolutePath, patched);

            return { json: { path: requestedPath, applied: true, newByteLength: patched.length } };
        } catch (error) {
            return { text: (error as Error).message, isError: true };
        }
    }

    private async loadCurrentContent(absolutePath: string): Promise<string> {
        const pending = this.editRecorder.getCurrentContent(absolutePath);
        if (pending !== undefined) return pending;

        const onDisk = await this.fileReader.readTextFile(absolutePath);
        return onDisk ?? '';
    }
}
