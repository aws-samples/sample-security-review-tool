import { NodeFileReader } from '../../../shared/file-system/node-file-reader.js';
import { AgentTool, ToolOutput } from '../types.js';
import { WorkspaceGuard } from '../workspace-guard.js';
import { EditRecorder } from '../edit-recorder.js';

/**
 * Replaces a literal substring in a file's staged contents.
 *
 * Design decisions (learned from the apply_patch failure mode):
 *   - Models cannot reliably emit unified diffs: hunk byte counts and CRLF/LF
 *     line endings defeat them. Literal search/replace sidesteps both.
 *   - The search is CRLF/LF-agnostic: we normalise both the file and the
 *     old_string to LF purely for the match. The file's existing line-ending
 *     style is preserved when writing back.
 *   - We require exactly one occurrence to avoid the model accidentally
 *     editing the wrong copy of a repeated snippet. The model can widen its
 *     old_string, or pass an explicit 1-based `occurrence` index, to
 *     disambiguate.
 */
export class EditFileTool implements AgentTool {
    private readonly fileReader = new NodeFileReader();

    constructor(
        private readonly guard: WorkspaceGuard,
        private readonly editRecorder: EditRecorder,
    ) {}

    public readonly definition = {
        toolSpec: {
            name: 'edit_file',
            description:
                'Replace a unique literal substring in a file. ' +
                'old_string must appear exactly once in the file; if it appears multiple times, widen the context until it is unique or pass the 1-based `occurrence` index. ' +
                'Do NOT emit diff headers, @@ line numbers, or leading +/-; just the literal text that is there now and the literal text you want instead. ' +
                'Line endings (CRLF vs LF) are handled for you.',
            inputSchema: {
                json: {
                    type: 'object',
                    properties: {
                        path: { type: 'string', description: 'Path relative to the project root.' },
                        old_string: { type: 'string', description: 'Literal text to find. Must match the file exactly (whitespace sensitive). Line endings are normalised.' },
                        new_string: { type: 'string', description: 'Literal replacement text.' },
                        occurrence: { type: 'integer', description: 'Optional 1-based index when old_string appears multiple times.' },
                    },
                    required: ['path', 'old_string', 'new_string'],
                },
            },
        },
    };

    public async invoke(input: Record<string, unknown>): Promise<ToolOutput> {
        const requestedPath = String(input.path ?? '');
        const oldString = String(input.old_string ?? '');
        const newString = String(input.new_string ?? '');
        const occurrence = this.parseOccurrence(input.occurrence);

        if (!requestedPath || !oldString) {
            return { text: 'Error: "path" and "old_string" are required.', isError: true };
        }

        try {
            const absolutePath = this.guard.resolve(requestedPath);
            const currentContent = await this.loadCurrentContent(absolutePath);
            const lineEnding = this.detectLineEnding(currentContent);

            const normalisedFile = this.toLf(currentContent);
            const normalisedOld = this.toLf(oldString);
            const normalisedNew = this.toLf(newString);

            const matchIndices = this.findAllIndices(normalisedFile, normalisedOld);

            if (matchIndices.length === 0) {
                return { text: `old_string not found in ${requestedPath}. Re-read the file and ensure the text matches exactly.`, isError: true };
            }

            if (matchIndices.length > 1 && occurrence === null) {
                return {
                    text: `old_string matches ${matchIndices.length} places in ${requestedPath}. Widen the context until it is unique, or pass an "occurrence" (1-${matchIndices.length}) to pick one.`,
                    isError: true,
                };
            }

            if (occurrence !== null && (occurrence < 1 || occurrence > matchIndices.length)) {
                return { text: `occurrence ${occurrence} is out of range (1-${matchIndices.length}).`, isError: true };
            }

            const chosenIndex = matchIndices[occurrence !== null ? occurrence - 1 : 0];
            const patchedLf =
                normalisedFile.slice(0, chosenIndex) +
                normalisedNew +
                normalisedFile.slice(chosenIndex + normalisedOld.length);

            const patched = this.restoreLineEndings(patchedLf, lineEnding);

            this.editRecorder.recordOriginal(absolutePath, currentContent);
            this.editRecorder.recordUpdate(absolutePath, patched);

            return {
                json: {
                    path: requestedPath,
                    matchCount: matchIndices.length,
                    occurrenceApplied: occurrence ?? 1,
                    newByteLength: patched.length,
                },
            };
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

    private parseOccurrence(value: unknown): number | null {
        if (value === undefined || value === null) return null;
        const asNumber = Number(value);
        return Number.isInteger(asNumber) ? asNumber : null;
    }

    private detectLineEnding(content: string): 'crlf' | 'lf' {
        return content.includes('\r\n') ? 'crlf' : 'lf';
    }

    private toLf(value: string): string {
        return value.replace(/\r\n/g, '\n');
    }

    private restoreLineEndings(lfContent: string, style: 'crlf' | 'lf'): string {
        if (style === 'lf') return lfContent;
        return lfContent.replace(/\n/g, '\r\n');
    }

    private findAllIndices(haystack: string, needle: string): number[] {
        if (needle.length === 0) return [];
        const indices: number[] = [];
        let offset = 0;
        while (true) {
            const next = haystack.indexOf(needle, offset);
            if (next === -1) break;
            indices.push(next);
            offset = next + needle.length;
        }
        return indices;
    }
}
