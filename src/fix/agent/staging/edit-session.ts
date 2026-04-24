import * as fs from 'fs/promises';
import { FixChange } from '../../types.js';
import { EditRecorder } from './edit-recorder.js';
import { WorkspaceGuard } from './workspace-guard.js';

export interface EditInput {
    path: string;
    lineRange: [number, number];
    newContent: string;
}

export type ApplyFailure =
    | { ok: false; reason: string; path?: string };

export type ApplyOk = { ok: true };
export type ApplyResult = ApplyOk | ApplyFailure;

interface FileBaseline {
    absolutePath: string;
    originalContent: string;
    originalLines: string[];
    fileExisted: boolean;
}

/**
 * Translates line-range edits into full-file replacements and hands them to
 * an EditRecorder. Each call to applyEdits starts from a fresh recorder so
 * that every apply_fix attempt is independent — no edit from a prior attempt
 * is ever implicitly carried into the next one.
 */
export class EditSession {
    private editRecorder = new EditRecorder();

    constructor(private readonly guard: WorkspaceGuard) {}

    public reset(): void {
        this.editRecorder = new EditRecorder();
    }

    public get recorder(): EditRecorder {
        return this.editRecorder;
    }

    public getChanges(): FixChange[] {
        return this.editRecorder.toFixChanges();
    }

    public async applyEdits(edits: EditInput[]): Promise<ApplyResult> {
        if (edits.length === 0) {
            return { ok: false, reason: 'At least one edit is required.' };
        }
        this.reset();

        const baselinesByPath = new Map<string, FileBaseline>();
        const resolvedEdits: { absolutePath: string; edit: EditInput }[] = [];

        for (const edit of edits) {
            const resolved = this.safeResolve(edit.path);
            if (!resolved.ok) return resolved;

            if (!baselinesByPath.has(resolved.absolutePath)) {
                baselinesByPath.set(resolved.absolutePath, await this.loadBaseline(resolved.absolutePath));
            }
            resolvedEdits.push({ absolutePath: resolved.absolutePath, edit });
        }

        const editsByPath = groupByPath(resolvedEdits);
        const pendingContentByPath = new Map<string, string[]>();

        for (const [absolutePath, fileEdits] of editsByPath) {
            const baseline = baselinesByPath.get(absolutePath)!;
            const result = applyEditsForFile(fileEdits, baseline);
            if (!result.ok) return result;
            pendingContentByPath.set(absolutePath, result.lines);
        }

        for (const [absolutePath, baseline] of baselinesByPath) {
            this.editRecorder.recordOriginal(absolutePath, baseline.originalContent, baseline.fileExisted);
        }
        for (const [absolutePath, lines] of pendingContentByPath) {
            this.editRecorder.recordUpdate(absolutePath, lines.join('\n'));
        }
        return { ok: true };
    }

    private safeResolve(inputPath: string): { ok: true; absolutePath: string } | ApplyFailure {
        try {
            return { ok: true, absolutePath: this.guard.resolve(inputPath) };
        } catch (error) {
            return { ok: false, reason: (error as Error).message, path: inputPath };
        }
    }

    private async loadBaseline(absolutePath: string): Promise<FileBaseline> {
        try {
            const originalContent = await fs.readFile(absolutePath, 'utf-8');
            return {
                absolutePath,
                originalContent,
                originalLines: originalContent.split(/\r?\n/),
                fileExisted: true,
            };
        } catch {
            return {
                absolutePath,
                originalContent: '',
                originalLines: [''],
                fileExisted: false,
            };
        }
    }
}

function groupByPath(resolvedEdits: { absolutePath: string; edit: EditInput }[]): Map<string, EditInput[]> {
    const map = new Map<string, EditInput[]>();
    for (const { absolutePath, edit } of resolvedEdits) {
        let list = map.get(absolutePath);
        if (!list) {
            list = [];
            map.set(absolutePath, list);
        }
        list.push(edit);
    }
    return map;
}

function editOriginalEnd(edit: EditInput): number {
    const [start, end] = edit.lineRange;
    return end >= start ? end : start - 1;
}

/**
 * Applies multiple edits to a single file, translating original-file line
 * numbers into post-edit coordinates. Edits are sorted top-to-bottom by
 * their original start line and applied with a running offset so the agent
 * can always reference the original file's line numbers.
 */
function applyEditsForFile(edits: EditInput[], baseline: FileBaseline): { ok: true; lines: string[] } | ApplyFailure {
    const sorted = [...edits].sort((a, b) => a.lineRange[0] - b.lineRange[0]);

    for (let i = 1; i < sorted.length; i++) {
        const prevEnd = editOriginalEnd(sorted[i - 1]);
        const currStart = sorted[i].lineRange[0];
        if (currStart <= prevEnd) {
            return {
                ok: false,
                reason: `Overlapping edits: [${sorted[i - 1].lineRange}] and [${sorted[i].lineRange}] overlap in the original file.`,
                path: sorted[i].path,
            };
        }
    }

    let currentLines = baseline.originalLines;
    let runningOffset = 0;

    for (const edit of sorted) {
        const adjusted: EditInput = {
            ...edit,
            lineRange: [edit.lineRange[0] + runningOffset, edit.lineRange[1] + runningOffset],
        };

        const applied = applyLineRangeEdit(currentLines, adjusted, baseline.fileExisted);
        if (!applied.ok) {
            return { ok: false, reason: applied.reason, path: edit.path };
        }
        currentLines = applied.lines;

        const isInsert = edit.lineRange[1] === edit.lineRange[0] - 1;
        const replacedCount = isInsert ? 0 : (edit.lineRange[1] - edit.lineRange[0] + 1);
        const insertedCount = edit.newContent.split(/\r?\n/).length;
        runningOffset += insertedCount - replacedCount;
    }

    return { ok: true, lines: currentLines };
}

type LineEditResult =
    | { ok: true; lines: string[] }
    | { ok: false; reason: string };

function applyLineRangeEdit(existingLines: string[], edit: EditInput, fileExisted: boolean): LineEditResult {
    const [start, end] = edit.lineRange;
    if (!Number.isInteger(start) || !Number.isInteger(end)) {
        return { ok: false, reason: `lineRange must contain integers, got [${start}, ${end}].` };
    }

    const lineCount = fileExisted ? existingLines.length : 0;

    // New file creation: path didn't exist AND caller used the [1, 0] sentinel.
    if (!fileExisted) {
        if (start === 1 && end === 0) {
            return { ok: true, lines: splitNewFileContent(edit.newContent) };
        }
        return {
            ok: false,
            reason: `Path ${edit.path} does not exist; use lineRange [1, 0] to create a new file.`,
        };
    }

    // Pure insert: [n, n-1] with 1 <= n <= lineCount + 1.
    if (end === start - 1) {
        if (start < 1 || start > lineCount + 1) {
            return {
                ok: false,
                reason: `Insert position ${start} is out of range (file has ${lineCount} lines).`,
            };
        }
        const newLines = splitInsertedContent(edit.newContent);
        const result = [...existingLines.slice(0, start - 1), ...newLines, ...existingLines.slice(start - 1)];
        return { ok: true, lines: result };
    }

    // Replacement: 1 <= start <= end <= lineCount.
    if (start < 1 || end < start || end > lineCount) {
        return {
            ok: false,
            reason: `lineRange [${start}, ${end}] is out of range (file has ${lineCount} lines).`,
        };
    }

    const newLines = splitInsertedContent(edit.newContent);
    const result = [...existingLines.slice(0, start - 1), ...newLines, ...existingLines.slice(end)];
    return { ok: true, lines: result };
}

function splitInsertedContent(content: string): string[] {
    // Preserve a trailing empty element when the caller's content ends with a newline
    // — the model intended that blank line to be inserted.
    return content.split(/\r?\n/);
}

function splitNewFileContent(content: string): string[] {
    return content.split(/\r?\n/);
}
