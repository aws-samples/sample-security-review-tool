import { FixChange } from '../types.js';

/**
 * Tracks in-memory edits proposed by the agent's apply_patch tool so that the
 * FixCoordinator can present them to the user before they are written to disk.
 *
 * Edits are accumulated per-file; the most recent proposed content wins.
 */
export class EditRecorder {
    private readonly proposedContent = new Map<string, string>();
    private readonly originalContent = new Map<string, string>();
    private readonly firstChangedLine = new Map<string, number>();

    public recordOriginal(filePath: string, original: string): void {
        if (!this.originalContent.has(filePath)) {
            this.originalContent.set(filePath, original);
        }
    }

    public recordUpdate(filePath: string, updated: string): void {
        const original = this.originalContent.get(filePath) ?? '';
        this.proposedContent.set(filePath, updated);
        this.firstChangedLine.set(filePath, this.findFirstDifferingLine(original, updated));
    }

    public toFixChanges(): FixChange[] {
        const changes: FixChange[] = [];
        for (const [filePath, updated] of this.proposedContent) {
            changes.push({
                filePath,
                original: this.originalContent.get(filePath) ?? '',
                updated,
                startingLineNumber: this.firstChangedLine.get(filePath) ?? 1,
            });
        }
        return changes;
    }

    public getCurrentContent(filePath: string): string | undefined {
        return this.proposedContent.get(filePath);
    }

    public hasEdits(): boolean {
        return this.proposedContent.size > 0;
    }

    private findFirstDifferingLine(before: string, after: string): number {
        const beforeLines = before.split('\n');
        const afterLines = after.split('\n');
        const limit = Math.min(beforeLines.length, afterLines.length);
        for (let i = 0; i < limit; i++) {
            if (beforeLines[i] !== afterLines[i]) return i + 1;
        }
        return limit + 1;
    }
}
